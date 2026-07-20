// ABOUTME: Loopback tests for the listening Server — establishment, clock-sync
// ABOUTME: replies, client/state handling, and graceful departure.
package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Sendspin/sendspin-go/pkg/protocol/playback"
	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
	"github.com/Sendspin/sendspin-go/pkg/protocol/session"
	"github.com/gorilla/websocket"
)

// harness stands up a Server behind a WebSocket endpoint and returns it, the
// http server, and a channel delivering each Handle call's return value.
func harness(t *testing.T, clock func() int64) (*Server, *httptest.Server, <-chan error) {
	t.Helper()
	serverID, _ := secure.GenerateIdentity()
	s, err := New(Config{
		Identity:              serverID,
		ServerName:            "test-server",
		AllowUnpairedPlayback: true,
		SourceKind:            playback.SourceLive,
		Clock:                 clock,
		NextGroupID:           counterIDs(),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	done := make(chan error, 4)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		done <- s.Handle(ws)
	}))
	t.Cleanup(srv.Close)
	return s, srv, done
}

func counterIDs() func() string {
	n := 0
	return func() string { n++; return "g" + string(rune('0'+n-1)) }
}

func dialAndEstablish(t *testing.T, srv *httptest.Server, id *secure.Identity) *secure.Conn {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, _, err := secure.ClientHandshake(ws, secure.ClientHandshakeConfig{Identity: id})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	hello := session.ClientHello{
		Name:           "test-player",
		TrustLevel:     session.TrustNone,
		SupportedRoles: []string{"player@v1"},
		UnpairedAccess: session.UnpairedAccess{Enabled: true},
	}
	if _, err := session.EstablishClient(conn, session.ClientConfig{Hello: hello, PSKCategory: session.PSKSentinel}); err != nil {
		t.Fatalf("establish client: %v", err)
	}
	return conn
}

func sendControl(t *testing.T, conn *secure.Conn, v any) {
	t.Helper()
	raw, err := session.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := conn.WriteMessage(secure.MsgTypeJSON, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readControl(t *testing.T, conn *secure.Conn) any {
	t.Helper()
	mt, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mt != secure.MsgTypeJSON {
		t.Fatalf("message type = %d, want JSON control", mt)
	}
	msg, err := session.Parse(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return msg
}

func TestServer_ClockSyncAndClientState(t *testing.T) {
	// A monotonically increasing test clock so receive < transmit.
	var tick int64
	clock := func() int64 { tick += 1000; return tick }
	s, srv, done := harness(t, clock)

	clientID, _ := secure.GenerateIdentity()
	conn := dialAndEstablish(t, srv, clientID)
	defer conn.Close()

	// Join sends the initial solo group/update.
	if gu, ok := readControl(t, conn).(*session.GroupUpdate); !ok || gu.PlaybackState != session.PlaybackStopped {
		t.Fatalf("expected initial group/update (stopped), got %#v", gu)
	}

	// client/time → server/time with the probe echoed and receive ≤ transmit.
	sendControl(t, conn, session.ClientTime{ClientTransmitted: 42})
	st, ok := readControl(t, conn).(*session.ServerTime)
	if !ok {
		t.Fatalf("expected server/time, got %T", st)
	}
	if st.ClientTransmitted != 42 {
		t.Errorf("client_transmitted echo = %d, want 42", st.ClientTransmitted)
	}
	if st.ServerReceived == 0 || st.ServerTransmitted < st.ServerReceived {
		t.Errorf("server_received=%d transmitted=%d not ordered", st.ServerReceived, st.ServerTransmitted)
	}

	// client/state makes the player available and sets its timing; a following
	// client/time round-trip is a barrier proving the state was applied.
	avail := true
	minBuf := 100
	sendControl(t, conn, session.ClientState{
		Available: &avail,
		Player:    &session.ClientPlayerState{MinBufferMs: &minBuf},
	})
	sendControl(t, conn, session.ClientTime{ClientTransmitted: 43})
	if st := readControl(t, conn).(*session.ServerTime); st.ClientTransmitted != 43 {
		t.Fatalf("barrier server/time echo = %d, want 43", st.ClientTransmitted)
	}
	g := s.Groups().GroupOf(clientID.ID())
	if g == nil {
		t.Fatal("client not in a group after client/state")
	}
	if sa := g.SendAheadMs(); sa != 100 {
		t.Errorf("group send-ahead = %d, want 100 (available, min_buffer 100)", sa)
	}

	// Graceful goodbye ends the loop cleanly and removes the client.
	sendControl(t, conn, session.ClientGoodbye{Reason: session.GoodbyeShutdown})
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Handle returned %v, want nil on goodbye", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return after goodbye")
	}
	if s.Groups().GroupOf(clientID.ID()) != nil {
		t.Error("client still in a group after goodbye")
	}
}

func TestServer_SocketCloseIsCleanDeparture(t *testing.T) {
	s, srv, done := harness(t, nil)
	clientID, _ := secure.GenerateIdentity()
	conn := dialAndEstablish(t, srv, clientID)
	readControl(t, conn) // initial group/update

	// Abrupt close (no goodbye) is still a clean departure.
	conn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Handle returned %v, want nil on socket close", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return after socket close")
	}
	if s.Groups().GroupOf(clientID.ID()) != nil {
		t.Error("client still tracked after disconnect")
	}
}
