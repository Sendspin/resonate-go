// ABOUTME: The server-side group manager — placement, availability-driven
// ABOUTME: solo/previous-group moves, and the group/update + stream lifecycle.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/Sendspin/sendspin-go/pkg/protocol/playback"
	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
)

// member is the manager's per-client bookkeeping: the connection and timing to
// re-add the client across group moves, its availability, its current group,
// and the external-source recovery state (previous group and the solo group the
// transition created).
type member struct {
	conn      *secure.Conn
	timing    playback.Timing
	byteRate  int
	available bool

	groupID     string
	prevGroupID string
	soloGroupID string
}

// GroupManagerConfig configures a GroupManager.
type GroupManagerConfig struct {
	// SourceKind is the source kind of the groups this manager creates.
	SourceKind playback.SourceKind
	// NextGroupID mints a fresh unique group_id. Nil uses a random 16-byte
	// hex generator; tests inject a deterministic counter.
	NextGroupID func() string
	// Now returns the server-clock time in microseconds, stamped into
	// stream/start and stream/end as server_transmitted. Nil stamps 0.
	Now func() int64
	// NameFor names a client's solo group. Nil leaves group_name empty.
	NameFor func(clientID string) string
}

// GroupManager owns every playback group for one server plus the per-client
// membership and previous-group bookkeeping the availability choreography
// needs. A newly-joined client lands in its own solo, stopped group. When a
// client reports available:false the manager quiesces it to a solo stopped
// group (remembering the previous group when it was sharing one); when it
// returns to available:true the manager does not auto-rejoin — the client stays
// solo and rejoins only via an explicit switch, which RejoinPreviousGroup
// serves. All methods are safe for concurrent use; control-message writes
// happen after the lock is released.
type GroupManager struct {
	mu      sync.Mutex
	kind    playback.SourceKind
	groups  map[string]*playback.Group
	states  map[string]PlaybackState
	names   map[string]string
	formats map[string]*StreamStartPlayer
	members map[string]*member
	nextID  func() string
	now     func() int64
	nameFor func(string) string
}

// NewGroupManager creates an empty GroupManager.
func NewGroupManager(cfg GroupManagerConfig) *GroupManager {
	nextID := cfg.NextGroupID
	if nextID == nil {
		nextID = randomGroupID
	}
	now := cfg.Now
	if now == nil {
		now = func() int64 { return 0 }
	}
	return &GroupManager{
		kind:    cfg.SourceKind,
		groups:  map[string]*playback.Group{},
		states:  map[string]PlaybackState{},
		names:   map[string]string{},
		formats: map[string]*StreamStartPlayer{},
		members: map[string]*member{},
		nextID:  nextID,
		now:     now,
		nameFor: cfg.NameFor,
	}
}

// pendingSend is a control message to write to a connection after the manager
// lock is released.
type pendingSend struct {
	conn *secure.Conn
	msg  any
}

func flush(sends []pendingSend) error {
	for _, s := range sends {
		if err := writeMessage(s.conn, s.msg); err != nil {
			return err
		}
	}
	return nil
}

// Join places a new client into its own solo, stopped group and notifies it of
// that group via group/update. The client starts unavailable — no audio flows
// until it reports available:true in its initial client/state. It returns the
// new group_id.
func (m *GroupManager) Join(clientID string, conn *secure.Conn, t playback.Timing, byteRate int) (string, error) {
	m.mu.Lock()
	gid := m.newSoloGroup(clientID, conn, t, byteRate)
	m.members[clientID] = &member{conn: conn, timing: t, byteRate: byteRate, groupID: gid}
	sends := []pendingSend{{conn, m.groupUpdate(gid)}}
	m.mu.Unlock()
	return gid, flush(sends)
}

// Leave removes a client from its group and forgets it, deleting the group if
// it becomes empty. Remaining members keep their group and state.
func (m *GroupManager) Leave(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mi := m.members[clientID]
	if mi == nil {
		return
	}
	m.groups[mi.groupID].Remove(clientID)
	m.deleteIfEmpty(mi.groupID)
	delete(m.members, clientID)
}

// ApplyClientState is the single entry point a client/state handler calls: it
// merges any player timing delta into the client's tracked timing, then applies
// an availability change through the group-move choreography. Absent fields are
// left unchanged.
func (m *GroupManager) ApplyClientState(clientID string, st ClientState) error {
	if st.Player != nil {
		m.mu.Lock()
		if mi := m.members[clientID]; mi != nil {
			mi.timing = mi.timing.MergeDelta(playback.TimingDelta{
				StaticDelayMs:      st.Player.StaticDelayMs,
				RequiredLeadTimeMs: st.Player.RequiredLeadTimeMs,
				MinBufferMs:        st.Player.MinBufferMs,
				BufferCapacity:     st.Player.BufferCapacity,
			})
			m.groups[mi.groupID].SetTiming(clientID, mi.timing)
		}
		m.mu.Unlock()
	}
	if st.Available != nil {
		return m.SetAvailable(clientID, *st.Available)
	}
	return nil
}

// SetAvailable applies an availability change. On available:false it quiesces
// the client to a solo stopped group (remembering the previous group when it
// shared one and ending the client's stream). On available:true it flips the
// gate but performs no auto-rejoin and no restart — the client stays where it
// is, per spec.
func (m *GroupManager) SetAvailable(clientID string, available bool) error {
	m.mu.Lock()
	mi := m.members[clientID]
	if mi == nil {
		m.mu.Unlock()
		return fmt.Errorf("unknown client %q", clientID)
	}
	mi.available = available
	m.groups[mi.groupID].SetAvailable(clientID, available)

	var sends []pendingSend
	if !available {
		sends = m.quiesceToSoloStopped(clientID)
	}
	m.mu.Unlock()
	return flush(sends)
}

// SetTiming replaces a client's tracked timing (e.g. from a client/state
// delta already merged elsewhere) and pushes it into its group.
func (m *GroupManager) SetTiming(clientID string, t playback.Timing) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mi := m.members[clientID]; mi != nil {
		mi.timing = t
		m.groups[mi.groupID].SetTiming(clientID, t)
	}
}

// StartGroup marks a group playing and opens a stream: it sends group/update
// (playing) and stream/start with the given player format to every member.
// The format is retained so a client that later rejoins a still-playing group
// receives a matching stream/start.
func (m *GroupManager) StartGroup(groupID string, format StreamStartPlayer) error {
	m.mu.Lock()
	g := m.groups[groupID]
	if g == nil {
		m.mu.Unlock()
		return fmt.Errorf("unknown group %q", groupID)
	}
	f := format
	m.states[groupID] = PlaybackPlaying
	m.formats[groupID] = &f
	start := StreamStart{ServerTransmitted: m.now(), Player: &f}
	update := m.groupUpdate(groupID)
	var sends []pendingSend
	for _, id := range m.memberIDs(groupID) {
		conn := m.members[id].conn
		sends = append(sends, pendingSend{conn, update}, pendingSend{conn, start})
	}
	m.mu.Unlock()
	return flush(sends)
}

// StopGroup marks a group stopped and ends its streams: it sends group/update
// (stopped) and stream/end to every member. A group already stopped is a no-op.
func (m *GroupManager) StopGroup(groupID string) error {
	m.mu.Lock()
	sends := m.stopGroupLocked(groupID)
	m.mu.Unlock()
	return flush(sends)
}

// MoveToGroup moves a client from its current group into an existing target
// group — the building block the switch command uses to gather players. It
// sends the client group/update for the target and, when the target is
// playing and the client is available, a matching stream/start. Moving is an
// explicit action, so it clears any external-source recovery state. Moving to
// the current group is a no-op.
func (m *GroupManager) MoveToGroup(clientID, targetGroupID string) error {
	m.mu.Lock()
	mi := m.members[clientID]
	target := m.groups[targetGroupID]
	if mi == nil {
		m.mu.Unlock()
		return fmt.Errorf("unknown client %q", clientID)
	}
	if target == nil {
		m.mu.Unlock()
		return fmt.Errorf("unknown group %q", targetGroupID)
	}
	if mi.groupID == targetGroupID {
		m.mu.Unlock()
		return nil
	}
	old := mi.groupID
	m.groups[old].Remove(clientID)
	m.deleteIfEmpty(old)
	target.Add(clientID, mi.conn, mi.timing, mi.byteRate)
	target.SetAvailable(clientID, mi.available)
	mi.groupID = targetGroupID
	mi.prevGroupID = ""
	mi.soloGroupID = ""

	sends := []pendingSend{{mi.conn, m.groupUpdate(targetGroupID)}}
	if mi.available && m.states[targetGroupID] == PlaybackPlaying && m.formats[targetGroupID] != nil {
		f := *m.formats[targetGroupID]
		sends = append(sends, pendingSend{mi.conn, StreamStart{ServerTransmitted: m.now(), Player: &f}})
	}
	m.mu.Unlock()
	return flush(sends)
}

// GroupOf returns the playback group a client currently belongs to, for the
// audio loop to broadcast into, or nil if the client is unknown.
func (m *GroupManager) GroupOf(clientID string) *playback.Group {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mi := m.members[clientID]; mi != nil {
		return m.groups[mi.groupID]
	}
	return nil
}

// GroupByID returns the playback group with the given id for the audio loop to
// broadcast into, or nil if there is no such group.
func (m *GroupManager) GroupByID(groupID string) *playback.Group {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.groups[groupID]
}

// GroupID returns the client's current group_id, or "" if unknown.
func (m *GroupManager) GroupID(clientID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mi := m.members[clientID]; mi != nil {
		return mi.groupID
	}
	return ""
}

// PlaybackStateOf returns a group's playback state, or "" if the group is
// unknown.
func (m *GroupManager) PlaybackStateOf(groupID string) PlaybackState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.states[groupID]
}

// RejoinPreviousGroup serves the switch command's previous-group priority: if
// the client is available and still sitting in the very solo group its
// external-source transition created, it moves back into the remembered
// previous group and, when that group is playing, receives a matching
// stream/start. It reports whether a rejoin happened; false means the normal
// switch cycle should proceed (the previous group is gone, or the client has
// since moved).
func (m *GroupManager) RejoinPreviousGroup(clientID string) (bool, error) {
	m.mu.Lock()
	mi := m.members[clientID]
	if mi == nil {
		m.mu.Unlock()
		return false, fmt.Errorf("unknown client %q", clientID)
	}
	if !m.shouldRejoin(mi) {
		m.mu.Unlock()
		return false, nil
	}
	prevGID := mi.prevGroupID
	mi.prevGroupID = ""
	mi.soloGroupID = ""
	prev := m.groups[prevGID]
	if prev == nil || prevGID == mi.groupID {
		m.mu.Unlock()
		return false, nil
	}

	solo := mi.groupID
	m.groups[solo].Remove(clientID)
	m.deleteIfEmpty(solo)
	prev.Add(clientID, mi.conn, mi.timing, mi.byteRate)
	prev.SetAvailable(clientID, mi.available)
	mi.groupID = prevGID

	sends := []pendingSend{{mi.conn, m.groupUpdate(prevGID)}}
	if m.states[prevGID] == PlaybackPlaying && m.formats[prevGID] != nil {
		f := *m.formats[prevGID]
		sends = append(sends, pendingSend{mi.conn, StreamStart{ServerTransmitted: m.now(), Player: &f}})
	}
	m.mu.Unlock()
	return true, flush(sends)
}

// --- locked helpers (caller holds m.mu) ---

// quiesceToSoloStopped moves a now-unavailable client out of any shared group.
// A client sharing a group is moved to a fresh solo stopped group with its
// previous group remembered and its stream ended; a client already alone has
// its group stopped in place. Returns the control-message sends to flush.
func (m *GroupManager) quiesceToSoloStopped(clientID string) []pendingSend {
	mi := m.members[clientID]
	g := m.groups[mi.groupID]
	if g.Len() > 1 {
		prevGID := mi.groupID
		wasPlaying := m.states[prevGID] == PlaybackPlaying
		var sends []pendingSend
		if wasPlaying {
			sends = append(sends, pendingSend{mi.conn, StreamEnd{ServerTransmitted: m.now()}})
		}
		g.Remove(clientID)
		m.deleteIfEmpty(prevGID)

		gid := m.newSoloGroup(clientID, mi.conn, mi.timing, mi.byteRate)
		m.groups[gid].SetAvailable(clientID, mi.available) // false here
		mi.groupID = gid
		mi.prevGroupID = prevGID
		mi.soloGroupID = gid
		sends = append(sends, pendingSend{mi.conn, m.groupUpdate(gid)})
		return sends
	}
	// Already solo: stop playback in place.
	return m.stopGroupLocked(mi.groupID)
}

func (m *GroupManager) stopGroupLocked(groupID string) []pendingSend {
	if m.groups[groupID] == nil || m.states[groupID] != PlaybackPlaying {
		return nil
	}
	m.states[groupID] = PlaybackStopped
	delete(m.formats, groupID)
	end := StreamEnd{ServerTransmitted: m.now()}
	update := m.groupUpdate(groupID)
	var sends []pendingSend
	for _, id := range m.memberIDs(groupID) {
		conn := m.members[id].conn
		sends = append(sends, pendingSend{conn, end}, pendingSend{conn, update})
	}
	return sends
}

// newSoloGroup creates a fresh stopped group holding just clientID and returns
// its group_id. It does not touch m.members[clientID].groupID — the caller sets
// that.
func (m *GroupManager) newSoloGroup(clientID string, conn *secure.Conn, t playback.Timing, byteRate int) string {
	gid := m.nextID()
	g := playback.NewGroup(m.kind)
	g.Add(clientID, conn, t, byteRate)
	m.groups[gid] = g
	m.states[gid] = PlaybackStopped
	if m.nameFor != nil {
		m.names[gid] = m.nameFor(clientID)
	}
	return gid
}

func (m *GroupManager) shouldRejoin(mi *member) bool {
	return mi.prevGroupID != "" &&
		mi.available &&
		mi.soloGroupID == mi.groupID &&
		m.groups[mi.groupID] != nil &&
		m.groups[mi.groupID].Len() == 1
}

func (m *GroupManager) deleteIfEmpty(groupID string) {
	if g := m.groups[groupID]; g != nil && g.Len() == 0 {
		delete(m.groups, groupID)
		delete(m.states, groupID)
		delete(m.names, groupID)
		delete(m.formats, groupID)
	}
}

func (m *GroupManager) groupUpdate(groupID string) GroupUpdate {
	return GroupUpdate{
		PlaybackState: m.states[groupID],
		GroupID:       groupID,
		GroupName:     m.names[groupID],
	}
}

func (m *GroupManager) memberIDs(groupID string) []string {
	var ids []string
	for id, mi := range m.members {
		if mi.groupID == groupID {
			ids = append(ids, id)
		}
	}
	return ids
}

func randomGroupID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
