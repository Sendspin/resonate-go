// ABOUTME: Loopback tests for the encrypted connection: full preamble over a
// ABOUTME: real WebSocket, bidirectional traffic, fragmentation, failure modes.
package secure

import (
	"bytes"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type loopbackResult struct {
	conn *Conn
	ci   ClientInit
	err  error
}

// startLoopbackServer runs an httptest WebSocket endpoint that performs the
// server side of the preamble and hands the resulting Conn to the callback.
func startLoopbackServer(t *testing.T, cfg ServerHandshakeConfig, serve func(*Conn, ClientInit)) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		conn, ci, err := ServerHandshake(ws, cfg)
		if err != nil {
			return // handshake failures close the socket; tests observe client side
		}
		serve(conn, ci)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func wsURL(srv *httptest.Server) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func dial(t *testing.T, srv *httptest.Server, cfg ClientHandshakeConfig) (*Conn, ServerInit, error) {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial(wsURL(srv), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return ClientHandshake(ws, cfg)
}

func TestConn_LoopbackBothSuites(t *testing.T) {
	for _, suite := range []Suite{SuiteChaChaPoly, SuiteAESGCM} {
		t.Run(string(suite), func(t *testing.T) {
			serverID, _ := GenerateIdentity()
			clientID, _ := GenerateIdentity()

			artwork := make([]byte, 180_000)
			rand.New(rand.NewSource(7)).Read(artwork)

			srvDone := make(chan error, 1)
			srv := startLoopbackServer(t, ServerHandshakeConfig{Identity: serverID}, func(conn *Conn, ci ClientInit) {
				defer conn.Close()
				srvDone <- func() error {
					if ci.ClientID != clientID.ID() {
						t.Errorf("server saw client_id %q, want %q", ci.ClientID, clientID.ID())
					}
					// server/hello equivalent.
					if err := conn.WriteJSON(map[string]any{"type": "server/hello", "payload": map[string]any{"name": "loopback"}}); err != nil {
						return err
					}
					// Expect a JSON reply from the client.
					msgType, payload, err := conn.ReadMessage()
					if err != nil {
						return err
					}
					if msgType != MsgTypeJSON || !bytes.Contains(payload, []byte("client/hello")) {
						t.Errorf("unexpected client message: type %d payload %.60s", msgType, payload)
					}
					// A fragmented artwork-sized binary message.
					return conn.WriteMessage(8, artwork)
				}()
			})

			conn, si, err := dial(t, srv, ClientHandshakeConfig{
				Identity: clientID,
				Suite:    suite,
			})
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			defer conn.Close()
			if si.ServerID != serverID.ID() {
				t.Errorf("client saw server_id %q, want %q", si.ServerID, serverID.ID())
			}
			if conn.PeerID() != serverID.ID() {
				t.Errorf("PeerID = %q, want server id", conn.PeerID())
			}

			msgType, payload, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("read server/hello: %v", err)
			}
			if msgType != MsgTypeJSON || !bytes.Contains(payload, []byte("server/hello")) {
				t.Fatalf("unexpected first message: type %d payload %.60s", msgType, payload)
			}

			if err := conn.WriteJSON(map[string]any{"type": "client/hello", "payload": map[string]any{"name": "loopback-client"}}); err != nil {
				t.Fatalf("write client/hello: %v", err)
			}

			msgType, payload, err = conn.ReadMessage()
			if err != nil {
				t.Fatalf("read artwork: %v", err)
			}
			if msgType != 8 || !bytes.Equal(payload, artwork) {
				t.Errorf("artwork message corrupted: type %d, %d bytes", msgType, len(payload))
			}

			if err := <-srvDone; err != nil {
				t.Fatalf("server side: %v", err)
			}
		})
	}
}

func TestConn_ExpectedServerIDMismatchFails(t *testing.T) {
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()
	other, _ := GenerateIdentity()

	srv := startLoopbackServer(t, ServerHandshakeConfig{Identity: serverID}, func(conn *Conn, _ ClientInit) { conn.Close() })

	_, _, err := dial(t, srv, ClientHandshakeConfig{
		Identity:         clientID,
		ExpectedServerID: other.ID(),
	})
	if err == nil {
		t.Fatal("handshake with mismatched expected server id succeeded")
	}
}

func TestConn_ClientRejectsUnknownPSK(t *testing.T) {
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()
	longTerm, _ := NewPSK()

	// Server offers a long-term PSK the client does not have.
	srv := startLoopbackServer(t, ServerHandshakeConfig{
		Identity:  serverID,
		SelectPSK: func(string) (PSK, error) { return longTerm, nil },
	}, func(conn *Conn, _ ClientInit) { conn.Close() })

	_, _, err := dial(t, srv, ClientHandshakeConfig{Identity: clientID})
	if err == nil {
		t.Fatal("handshake with unknown psk_id succeeded")
	}
}

func TestConn_HandshakeTimeout(t *testing.T) {
	// A server that upgrades but never speaks.
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		time.Sleep(5 * time.Second)
		ws.Close()
	}))
	defer srv.Close()

	clientID, _ := GenerateIdentity()
	ws, _, err := websocket.DefaultDialer.Dial(wsURL(srv), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	start := time.Now()
	_, _, err = ClientHandshake(ws, ClientHandshakeConfig{
		Identity:         clientID,
		HandshakeTimeout: 300 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("handshake against a silent server succeeded")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("timeout took %v, want ~300ms", elapsed)
	}
}

func TestConn_TextFrameInTransportModeFails(t *testing.T) {
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()

	srv := startLoopbackServer(t, ServerHandshakeConfig{Identity: serverID}, func(conn *Conn, _ ClientInit) {
		// Violate the spec: send a text frame after transport mode.
		conn.ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"oops"}`))
		time.Sleep(200 * time.Millisecond)
		conn.Close()
	})

	conn, _, err := dial(t, srv, ClientHandshakeConfig{Identity: clientID})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer conn.Close()
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("text frame in transport mode accepted")
	}
}
