// ABOUTME: The playback Group — member sessions, their timing, the group
// ABOUTME: send-ahead, and buffer-paced fan-out of player-audio chunks.
package playback

import "sync"

// ChunkWriter is the transport sink a group member receives audio chunks on.
// *secure.Conn satisfies it, so a Group drives real connections without this
// package importing the transport.
type ChunkWriter interface {
	WriteMessage(msgType byte, payload []byte) error
}

// Member is one player in a playback group: its connection, current timing,
// negotiated codec byte rate, availability, and buffer accounting. Fields are
// mutated only through the owning Group so its lock guards them.
type Member struct {
	// ID is the member's client_id.
	ID string

	conn      ChunkWriter
	timing    Timing
	byteRate  int // codec output bytes per second, for buffer_capacity math
	available bool
	tracker   *BufferTracker
}

// Timing returns the member's current timing state.
func (m *Member) Timing() Timing { return m.timing }

// Available reports whether the member has signalled it is ready for audio
// (initial client/state with available:true). The server MUST NOT stream to a
// member before that.
func (m *Member) Available() bool { return m.available }

// Group is a playback group: a set of player members served one synchronized
// stream. It owns each member's timing and buffer state, derives the common
// send-ahead from the members' timings, and fans audio chunks out to every
// available member under that member's buffer_capacity.
//
// Membership and timing mutators (Add/Remove/SetTiming/SetAvailable) are safe
// for concurrent use. Broadcast must be called from a single goroutine — the
// audio loop — which owns the per-member buffer trackers.
type Group struct {
	kind SourceKind

	mu      sync.Mutex
	members map[string]*Member
	order   []string // stable join order for deterministic fan-out
}

// NewGroup creates an empty group serving the given source kind (live sources
// take a minimal lead; buffered sources may lead further ahead).
func NewGroup(kind SourceKind) *Group {
	return &Group{kind: kind, members: map[string]*Member{}}
}

// SourceKind returns the group's source kind.
func (g *Group) SourceKind() SourceKind { return g.kind }

// Add joins a member with its initial timing and codec byte rate. The member
// starts unavailable — it receives no audio until SetAvailable(true), matching
// the spec's "no binary data before the initial client/state" rule. Re-adding
// an existing ID replaces its connection and timing but preserves join order.
func (g *Group) Add(id string, conn ChunkWriter, t Timing, codecByteRate int) *Member {
	g.mu.Lock()
	defer g.mu.Unlock()
	m, ok := g.members[id]
	if !ok {
		m = &Member{ID: id, tracker: NewBufferTracker(t.BufferCapacity)}
		g.members[id] = m
		g.order = append(g.order, id)
	}
	m.conn = conn
	m.timing = t
	m.byteRate = codecByteRate
	m.tracker.SetCapacity(t.BufferCapacity)
	return m
}

// Remove drops a member from the group.
func (g *Group) Remove(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.members[id]; !ok {
		return
	}
	delete(g.members, id)
	for i, o := range g.order {
		if o == id {
			g.order = append(g.order[:i], g.order[i+1:]...)
			break
		}
	}
}

// SetTiming replaces a member's timing (from a client/state update) and revises
// its buffer_capacity. It is a no-op for an unknown member.
func (g *Group) SetTiming(id string, t Timing) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if m, ok := g.members[id]; ok {
		m.timing = t
		m.tracker.SetCapacity(t.BufferCapacity)
	}
}

// SetAvailable toggles a member's availability. A member only receives audio
// while available. It is a no-op for an unknown member.
func (g *Group) SetAvailable(id string, available bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if m, ok := g.members[id]; ok {
		m.available = available
	}
}

// SetCodecByteRate updates a member's codec output byte rate, e.g. after
// renegotiation. It is a no-op for an unknown member.
func (g *Group) SetCodecByteRate(id string, byteRate int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if m, ok := g.members[id]; ok {
		m.byteRate = byteRate
	}
}

// Len returns the number of members (available or not).
func (g *Group) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.members)
}

// SendAheadMs is the group's common send-ahead: the maximum per-player
// send-ahead across available members, so every streaming player has at least
// its required lead. Returns 0 when no member is available.
func (g *Group) SendAheadMs() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	max := 0
	for _, id := range g.order {
		m := g.members[id]
		if !m.available {
			continue
		}
		if sa := PerPlayerSendAheadMs(m.timing, g.kind); sa > max {
			max = sa
		}
	}
	return max
}

// BroadcastResult reports how one member fared for a single chunk.
type BroadcastResult struct {
	MemberID string
	// Sent is true when the chunk was written to the member.
	Sent bool
	// Backpressure is true when the member was skipped because its
	// buffer_capacity had no room — normal flow control, not an error.
	Backpressure bool
	// Err is non-nil when the write failed; the member's connection is broken
	// and the caller should remove it.
	Err error
}

// Broadcast fans one audio chunk out to every available member, paced by each
// member's buffer_capacity. payloadFor returns the member's codec-specific
// encoded audio for this chunk (players may negotiate different codecs, so the
// bytes differ per member) — returning nil skips that member. For each member
// the group prunes already-played audio as of nowUS, and if the member's buffer
// has room it prepends the timestamp header and writes a player-audio message.
//
// timestampUS is the chunk's playback time on the server clock; durationUS is
// its playback length (20 000 for a 20 ms chunk). The returned slice reports
// one entry per available member with a non-nil payload, in join order.
func (g *Group) Broadcast(nowUS, timestampUS, durationUS int64, payloadFor func(*Member) []byte) []BroadcastResult {
	g.mu.Lock()
	snapshot := make([]*Member, 0, len(g.order))
	for _, id := range g.order {
		if m := g.members[id]; m.available {
			snapshot = append(snapshot, m)
		}
	}
	g.mu.Unlock()

	var results []BroadcastResult
	endUS := timestampUS + durationUS
	for _, m := range snapshot {
		audio := payloadFor(m)
		if audio == nil {
			continue
		}
		m.tracker.Prune(nowUS)
		if !m.tracker.CanQueue(len(audio), durationUS) {
			results = append(results, BroadcastResult{MemberID: m.ID, Backpressure: true})
			continue
		}
		if err := m.conn.WriteMessage(PlayerAudioMsgType, EncodeAudioChunk(timestampUS, audio)); err != nil {
			results = append(results, BroadcastResult{MemberID: m.ID, Err: err})
			continue
		}
		m.tracker.Register(endUS, len(audio), durationUS)
		results = append(results, BroadcastResult{MemberID: m.ID, Sent: true})
	}
	return results
}
