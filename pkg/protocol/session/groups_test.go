// ABOUTME: Tests for the GroupManager — solo placement, availability-driven
// ABOUTME: moves, previous-group rejoin, over real encrypted connections.
package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Sendspin/sendspin-go/pkg/protocol/playback"
	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
	"github.com/gorilla/websocket"
)

// connPair returns a connected server/client pair of established secure.Conns.
func connPair(t *testing.T) (server, client *secure.Conn) {
	t.Helper()
	serverID, _ := secure.GenerateIdentity()
	clientID, _ := secure.GenerateIdentity()
	ch := make(chan *secure.Conn, 1)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c, _, err := secure.ServerHandshake(ws, secure.ServerHandshakeConfig{Identity: serverID})
		if err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		ch <- c
	}))
	t.Cleanup(srv.Close)

	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client, _, err = secure.ClientHandshake(ws, secure.ClientHandshakeConfig{Identity: clientID})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	return <-ch, client
}

// readMsg reads one JSON control message off a client conn and parses it.
func readMsg(t *testing.T, c *secure.Conn) any {
	t.Helper()
	mt, payload, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mt != secure.MsgTypeJSON {
		t.Fatalf("message type = %d, want JSON control", mt)
	}
	msg, err := Parse(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return msg
}

func mustGroupUpdate(t *testing.T, c *secure.Conn) *GroupUpdate {
	t.Helper()
	msg := readMsg(t, c)
	gu, ok := msg.(*GroupUpdate)
	if !ok {
		t.Fatalf("got %T, want *GroupUpdate", msg)
	}
	return gu
}

// counterIDs hands out deterministic group ids g0, g1, g2, ...
func counterIDs() func() string {
	var n int64
	return func() string { return "g" + string(rune('0'+atomic.AddInt64(&n, 1)-1)) }
}

func newTestManager() *GroupManager {
	return NewGroupManager(GroupManagerConfig{
		SourceKind:  playback.SourceLive,
		NextGroupID: counterIDs(),
		Now:         func() int64 { return 1_000 },
	})
}

func TestGroupManager_JoinCreatesSoloStoppedGroup(t *testing.T) {
	m := newTestManager()
	sc, cc := connPair(t)
	defer cc.Close()

	gid, err := m.Join("A", sc, playback.Timing{MinBufferMs: 100}, 0)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	gu := mustGroupUpdate(t, cc)
	if gu.GroupID != gid || gu.PlaybackState != PlaybackStopped {
		t.Errorf("group/update = %+v, want group %s stopped", gu, gid)
	}
	if m.GroupID("A") != gid {
		t.Errorf("GroupID(A) = %q, want %q", m.GroupID("A"), gid)
	}
}

func TestGroupManager_SoloUnavailableStopsInPlace(t *testing.T) {
	m := newTestManager()
	sc, cc := connPair(t)
	defer cc.Close()

	gid, _ := m.Join("A", sc, playback.Timing{MinBufferMs: 100}, 0)
	mustGroupUpdate(t, cc) // solo group/update from join
	if err := m.SetAvailable("A", true); err != nil {
		t.Fatal(err)
	}
	if err := m.StartGroup(gid, StreamStartPlayer{Codec: "pcm", Channels: 2, SampleRate: 48000, BitDepth: 16}); err != nil {
		t.Fatal(err)
	}
	if gu := mustGroupUpdate(t, cc); gu.PlaybackState != PlaybackPlaying {
		t.Errorf("start group/update = %+v, want playing", gu)
	}
	if _, ok := readMsg(t, cc).(*StreamStart); !ok {
		t.Fatal("expected stream/start after StartGroup")
	}

	// Going unavailable while solo: stop in place, same group id.
	if err := m.SetAvailable("A", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := readMsg(t, cc).(*StreamEnd); !ok {
		t.Fatal("expected stream/end on unavailable")
	}
	gu := mustGroupUpdate(t, cc)
	if gu.GroupID != gid || gu.PlaybackState != PlaybackStopped {
		t.Errorf("stop group/update = %+v, want same group %s stopped", gu, gid)
	}
	if m.GroupID("A") != gid {
		t.Errorf("solo client moved groups: %q != %q", m.GroupID("A"), gid)
	}
	if m.PlaybackStateOf(gid) != PlaybackStopped {
		t.Error("group not marked stopped")
	}
}

func TestGroupManager_MultiClientUnavailableMovesToSoloThenRejoin(t *testing.T) {
	m := newTestManager()
	scA, ccA := connPair(t)
	scB, ccB := connPair(t)
	defer ccA.Close()
	defer ccB.Close()

	gA, _ := m.Join("A", scA, playback.Timing{MinBufferMs: 100}, 0)
	mustGroupUpdate(t, ccA) // A solo
	_, _ = m.Join("B", scB, playback.Timing{MinBufferMs: 100}, 0)
	mustGroupUpdate(t, ccB) // B solo

	_ = m.SetAvailable("A", true)
	_ = m.SetAvailable("B", true)

	// Gather B into A's group, then start playing.
	if err := m.MoveToGroup("B", gA); err != nil {
		t.Fatal(err)
	}
	if gu := mustGroupUpdate(t, ccB); gu.GroupID != gA {
		t.Errorf("B move group/update = %+v, want group %s", gu, gA)
	}
	if err := m.StartGroup(gA, StreamStartPlayer{Codec: "pcm", Channels: 2, SampleRate: 48000, BitDepth: 16}); err != nil {
		t.Fatal(err)
	}
	// Both members get group/update(playing) + stream/start.
	for _, cc := range []*secure.Conn{ccA, ccB} {
		if gu := mustGroupUpdate(t, cc); gu.PlaybackState != PlaybackPlaying {
			t.Errorf("start update = %+v, want playing", gu)
		}
		if _, ok := readMsg(t, cc).(*StreamStart); !ok {
			t.Fatal("expected stream/start")
		}
	}

	// B goes unavailable from a shared, playing group: stream/end then a move
	// to a fresh solo stopped group. A is untouched.
	if err := m.SetAvailable("B", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := readMsg(t, ccB).(*StreamEnd); !ok {
		t.Fatal("expected stream/end for moved client")
	}
	guB := mustGroupUpdate(t, ccB)
	if guB.GroupID == gA || guB.PlaybackState != PlaybackStopped {
		t.Errorf("B move update = %+v, want a new group, stopped", guB)
	}
	if m.GroupID("A") != gA || m.PlaybackStateOf(gA) != PlaybackPlaying {
		t.Errorf("A disturbed: group=%q state=%q", m.GroupID("A"), m.PlaybackStateOf(gA))
	}
	if m.GroupID("B") == gA {
		t.Error("B still in shared group after unavailable")
	}

	// available:true must NOT auto-rejoin — B stays in its solo group.
	if err := m.SetAvailable("B", true); err != nil {
		t.Fatal(err)
	}
	if m.GroupID("B") == gA {
		t.Error("available:true auto-rejoined B — spec forbids it")
	}

	// Explicit rejoin (switch's previous-group priority) puts B back in A's
	// still-playing group with a fresh stream/start.
	ok, err := m.RejoinPreviousGroup("B")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("RejoinPreviousGroup returned false, want a rejoin")
	}
	if gu := mustGroupUpdate(t, ccB); gu.GroupID != gA || gu.PlaybackState != PlaybackPlaying {
		t.Errorf("rejoin update = %+v, want group %s playing", gu, gA)
	}
	if _, ok := readMsg(t, ccB).(*StreamStart); !ok {
		t.Fatal("expected stream/start on rejoin into a playing group")
	}
	if m.GroupID("B") != gA {
		t.Errorf("after rejoin B group = %q, want %q", m.GroupID("B"), gA)
	}
}

func TestGroupManager_RejoinDeclinedWhenPreviousGroupGone(t *testing.T) {
	m := newTestManager()
	scA, ccA := connPair(t)
	scB, ccB := connPair(t)
	defer ccA.Close()
	defer ccB.Close()

	gA, _ := m.Join("A", scA, playback.Timing{}, 0)
	mustGroupUpdate(t, ccA)
	_, _ = m.Join("B", scB, playback.Timing{}, 0)
	mustGroupUpdate(t, ccB)
	_ = m.SetAvailable("A", true)
	_ = m.SetAvailable("B", true)

	_ = m.MoveToGroup("B", gA)
	mustGroupUpdate(t, ccB)
	_ = m.SetAvailable("B", false) // B moves to solo, remembers gA
	mustGroupUpdate(t, ccB)        // solo group/update (gA was stopped, so no stream/end)
	_ = m.SetAvailable("B", true)

	// A leaves entirely, dissolving the previous group gA.
	m.Leave("A")
	if m.GroupOf("A") != nil {
		t.Error("A still tracked after Leave")
	}

	ok, err := m.RejoinPreviousGroup("B")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("rejoin succeeded though the previous group is gone")
	}
}
