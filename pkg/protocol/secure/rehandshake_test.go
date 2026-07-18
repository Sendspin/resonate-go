// ABOUTME: Tests for the in-band re-handshake: key swap over a live channel,
// ABOUTME: traffic under new keys, and hash chaining.
package secure

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRehandshake_SwapsKeysInBand(t *testing.T) {
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()

	srvConnCh := make(chan *Conn, 1)
	srv := startLoopbackServer(t, ServerHandshakeConfig{Identity: serverID}, func(conn *Conn, _ ClientInit) {
		srvConnCh <- conn
	})
	clientConn, _, err := dial(t, srv, ClientHandshakeConfig{Identity: clientID})
	if err != nil {
		t.Fatal(err)
	}
	serverConn := <-srvConnCh
	defer serverConn.Close()
	defer clientConn.Close()

	oldHash := serverConn.HandshakeHash()
	newPSK, _ := NewPSK()

	// Server initiates; client sees the noise/handshake frame and responds.
	errCh := make(chan error, 1)
	go func() { errCh <- serverConn.RehandshakeInitiate(newPSK) }()

	msgType, payload, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("client read rehandshake: %v", err)
	}
	var env struct {
		Type string `json:"type"`
	}
	if msgType != MsgTypeJSON || json.Unmarshal(payload, &env) != nil || env.Type != "noise/handshake" {
		t.Fatalf("expected noise/handshake frame, got type %d %.60s", msgType, payload)
	}
	err = clientConn.RehandshakeRespond(payload, func(id string) (PSK, bool) {
		if id != newPSK.ID() {
			t.Errorf("rehandshake announced psk_id %q, want %q", id, newPSK.ID())
			return PSK{}, false
		}
		return newPSK, true
	})
	if err != nil {
		t.Fatalf("client rehandshake: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server rehandshake: %v", err)
	}

	// Hash changed and matches on both sides.
	if bytes.Equal(oldHash, serverConn.HandshakeHash()) {
		t.Error("handshake hash unchanged after rehandshake")
	}
	if !bytes.Equal(serverConn.HandshakeHash(), clientConn.HandshakeHash()) {
		t.Error("post-rehandshake hashes differ between sides")
	}

	// Traffic flows under the new keys, both directions.
	if err := serverConn.WriteMessage(4, []byte("audio-after-rekey")); err != nil {
		t.Fatal(err)
	}
	mt, pl, err := clientConn.ReadMessage()
	if err != nil || mt != 4 || string(pl) != "audio-after-rekey" {
		t.Fatalf("post-rekey server→client: type=%d payload=%q err=%v", mt, pl, err)
	}
	if err := clientConn.WriteMessage(MsgTypeJSON, []byte(`{"type":"client/time","payload":{"client_transmitted":1}}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := serverConn.ReadMessage(); err != nil {
		t.Fatalf("post-rekey client→server: %v", err)
	}
}

func TestRehandshake_WrongPSKFails(t *testing.T) {
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()

	srvConnCh := make(chan *Conn, 1)
	srv := startLoopbackServer(t, ServerHandshakeConfig{Identity: serverID}, func(conn *Conn, _ ClientInit) {
		srvConnCh <- conn
	})
	clientConn, _, err := dial(t, srv, ClientHandshakeConfig{Identity: clientID})
	if err != nil {
		t.Fatal(err)
	}
	serverConn := <-srvConnCh
	defer serverConn.Close()
	defer clientConn.Close()

	newPSK, _ := NewPSK()
	wrong, _ := NewPSK()

	errCh := make(chan error, 1)
	go func() { errCh <- serverConn.RehandshakeInitiate(newPSK) }()

	_, payload, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	// Client resolves the right psk_id to the wrong bytes.
	if err := clientConn.RehandshakeRespond(payload, func(string) (PSK, bool) { return wrong, true }); err != nil {
		t.Fatalf("responder side: %v", err)
	}
	if err := <-errCh; err == nil {
		t.Error("initiator accepted rehandshake message 2 built with the wrong PSK")
	}
}
