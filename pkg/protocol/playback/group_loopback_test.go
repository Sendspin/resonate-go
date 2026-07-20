// ABOUTME: End-to-end loopback — a Group drives audio chunks over a real
// ABOUTME: encrypted secure.Conn and the client reads them back off the wire.
package playback_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sendspin/sendspin-go/pkg/protocol/playback"
	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
	"github.com/gorilla/websocket"
)

// TestGroup_LoopbackStream stands up an encrypted transport, wires the
// server-side connection into a Group, broadcasts three chunks, and confirms
// the client reads each one back as a player-audio message with the right
// timestamp and payload — proving Group → Conn.WriteMessage → the wire →
// Conn.ReadMessage carries audio intact through the Noise session.
func TestGroup_LoopbackStream(t *testing.T) {
	serverID, _ := secure.GenerateIdentity()
	clientID, _ := secure.GenerateIdentity()

	serverConnCh := make(chan *secure.Conn, 1)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn, _, err := secure.ServerHandshake(ws, secure.ServerHandshakeConfig{Identity: serverID})
		if err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		serverConnCh <- conn
	}))
	defer srv.Close()

	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	clientConn, _, err := secure.ClientHandshake(ws, secure.ClientHandshakeConfig{Identity: clientID})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer clientConn.Close()

	serverConn := <-serverConnCh
	defer serverConn.Close()

	g := playback.NewGroup(playback.SourceLive)
	g.Add(clientID.ID(), serverConn, playback.Timing{MinBufferMs: 100}, 0)
	g.SetAvailable(clientID.ID(), true)

	chunks := []struct {
		ts    int64
		audio []byte
	}{
		{1_000_000, []byte{0x11, 0x22}},
		{1_020_000, []byte{0x33, 0x44, 0x55}},
		{1_040_000, []byte{0x66}},
	}

	go func() {
		for i, c := range chunks {
			res := g.Broadcast(int64(i)*20_000, c.ts, 20_000, func(*playback.Member) []byte { return c.audio })
			if len(res) != 1 || !res[0].Sent {
				t.Errorf("chunk %d broadcast = %+v, want sent", i, res)
			}
		}
	}()

	for i, want := range chunks {
		msgType, body, err := clientConn.ReadMessage()
		if err != nil {
			t.Fatalf("read chunk %d: %v", i, err)
		}
		if msgType != playback.PlayerAudioMsgType {
			t.Fatalf("chunk %d type = %d, want %d", i, msgType, playback.PlayerAudioMsgType)
		}
		ts, audio, err := playback.ParseAudioChunk(body)
		if err != nil {
			t.Fatalf("chunk %d parse: %v", i, err)
		}
		if ts != want.ts {
			t.Errorf("chunk %d ts = %d, want %d", i, ts, want.ts)
		}
		if string(audio) != string(want.audio) {
			t.Errorf("chunk %d audio = %v, want %v", i, audio, want.audio)
		}
	}
}
