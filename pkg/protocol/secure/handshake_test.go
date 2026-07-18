// ABOUTME: Tests for the KKpsk2 handshake: loopback across both suites, PSK
// ABOUTME: selection, and failure modes (tamper, wrong keys, replay).
package secure

import (
	"bytes"
	"testing"
)

// handshakePeers builds a server/client identity pair plus the init-message
// prologue exactly as a real connection would.
func handshakePeers(t *testing.T, suite Suite) (server, client *Identity, prologue []byte) {
	t.Helper()
	server, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err = GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ciRaw, err := EncodeClientInit(ClientInit{ClientID: client.ID(), Version: CoreVersion, Suite: suite})
	if err != nil {
		t.Fatal(err)
	}
	siRaw, err := EncodeServerInit(ServerInit{ServerID: server.ID(), Version: CoreVersion})
	if err != nil {
		t.Fatal(err)
	}
	return server, client, Prologue(ciRaw, siRaw)
}

// runHandshake drives a complete handshake and returns both sessions.
func runHandshake(t *testing.T, suite Suite, psk PSK, selectPSK func(string) (PSK, bool)) (serverSess, clientSess *Session) {
	t.Helper()
	server, client, prologue := handshakePeers(t, suite)

	init, err := NewInitiator(InitiatorConfig{
		Identity: server, PeerPublicKey: client.PublicKey(),
		Suite: suite, Prologue: prologue, PSK: psk,
	})
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	resp, err := NewResponder(ResponderConfig{
		Identity: client, PeerPublicKey: server.PublicKey(),
		Suite: suite, Prologue: prologue, SelectPSK: selectPSK,
	})
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}

	msg1, err := init.Message1(psk.ID())
	if err != nil {
		t.Fatalf("Message1: %v", err)
	}
	msg2, clientSess, err := resp.Accept(msg1)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	serverSess, err = init.Finish(msg2)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return serverSess, clientSess
}

func sentinelSelector(id string) (PSK, bool) {
	s := SentinelPSK()
	if id == s.ID() {
		return s, true
	}
	return PSK{}, false
}

func TestHandshake_LoopbackBothSuites(t *testing.T) {
	for _, suite := range []Suite{SuiteChaChaPoly, SuiteAESGCM} {
		t.Run(string(suite), func(t *testing.T) {
			serverSess, clientSess := runHandshake(t, suite, SentinelPSK(), sentinelSelector)

			if !bytes.Equal(serverSess.HandshakeHash(), clientSess.HandshakeHash()) {
				t.Error("handshake hashes differ between sides")
			}
			if len(serverSess.HandshakeHash()) != 32 {
				t.Errorf("handshake hash is %d bytes, want 32 (SHA-256)", len(serverSess.HandshakeHash()))
			}

			// Server → client.
			ct, err := serverSess.Encrypt([]byte("hello from server"))
			if err != nil {
				t.Fatalf("server Encrypt: %v", err)
			}
			pt, err := clientSess.Decrypt(ct)
			if err != nil {
				t.Fatalf("client Decrypt: %v", err)
			}
			if string(pt) != "hello from server" {
				t.Errorf("round trip = %q", pt)
			}

			// Client → server.
			ct, err = clientSess.Encrypt([]byte("hello from client"))
			if err != nil {
				t.Fatalf("client Encrypt: %v", err)
			}
			pt, err = serverSess.Decrypt(ct)
			if err != nil {
				t.Fatalf("server Decrypt: %v", err)
			}
			if string(pt) != "hello from client" {
				t.Errorf("round trip = %q", pt)
			}
		})
	}
}

func TestHandshake_SelectsLongTermPSKByID(t *testing.T) {
	longTerm, err := NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	decoy, err := NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	candidates := map[string]PSK{
		SentinelPSK().ID(): SentinelPSK(),
		decoy.ID():         decoy,
		longTerm.ID():      longTerm,
	}
	var selectedID string
	serverSess, clientSess := runHandshake(t, SuiteChaChaPoly, longTerm, func(id string) (PSK, bool) {
		selectedID = id
		p, ok := candidates[id]
		return p, ok
	})
	if selectedID != longTerm.ID() {
		t.Errorf("client selected psk_id %q, want %q", selectedID, longTerm.ID())
	}
	ct, _ := serverSess.Encrypt([]byte("keyed"))
	if _, err := clientSess.Decrypt(ct); err != nil {
		t.Errorf("transport broken after long-term PSK handshake: %v", err)
	}
}

func TestHandshake_UnknownPSKIDFails(t *testing.T) {
	server, client, prologue := handshakePeers(t, SuiteChaChaPoly)
	unknown, _ := NewPSK()

	init, _ := NewInitiator(InitiatorConfig{
		Identity: server, PeerPublicKey: client.PublicKey(),
		Suite: SuiteChaChaPoly, Prologue: prologue, PSK: unknown,
	})
	resp, _ := NewResponder(ResponderConfig{
		Identity: client, PeerPublicKey: server.PublicKey(),
		Suite: SuiteChaChaPoly, Prologue: prologue, SelectPSK: sentinelSelector,
	})

	msg1, err := init.Message1(unknown.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := resp.Accept(msg1); err == nil {
		t.Error("handshake with unknown psk_id succeeded, want failure")
	}
}

func TestHandshake_WrongPSKValueFailsAtInitiator(t *testing.T) {
	server, client, prologue := handshakePeers(t, SuiteChaChaPoly)
	real, _ := NewPSK()
	corrupt, _ := NewPSK()

	init, _ := NewInitiator(InitiatorConfig{
		Identity: server, PeerPublicKey: client.PublicKey(),
		Suite: SuiteChaChaPoly, Prologue: prologue, PSK: real,
	})
	// Client's store maps the right psk_id to the wrong bytes (corrupt store).
	resp, _ := NewResponder(ResponderConfig{
		Identity: client, PeerPublicKey: server.PublicKey(),
		Suite: SuiteChaChaPoly, Prologue: prologue,
		SelectPSK: func(string) (PSK, bool) { return corrupt, true },
	})

	msg1, err := init.Message1(real.ID())
	if err != nil {
		t.Fatal(err)
	}
	msg2, _, err := resp.Accept(msg1)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if _, err := init.Finish(msg2); err == nil {
		t.Error("initiator accepted message 2 built with the wrong PSK")
	}
}

func TestHandshake_PrologueMismatchFails(t *testing.T) {
	server, client, prologue := handshakePeers(t, SuiteChaChaPoly)

	init, _ := NewInitiator(InitiatorConfig{
		Identity: server, PeerPublicKey: client.PublicKey(),
		Suite: SuiteChaChaPoly, Prologue: prologue, PSK: SentinelPSK(),
	})
	tampered := append(append([]byte(nil), prologue...), '!')
	resp, _ := NewResponder(ResponderConfig{
		Identity: client, PeerPublicKey: server.PublicKey(),
		Suite: SuiteChaChaPoly, Prologue: tampered, SelectPSK: sentinelSelector,
	})

	msg1, err := init.Message1(SentinelPSK().ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := resp.Accept(msg1); err == nil {
		t.Error("handshake with mismatched prologue succeeded, want failure")
	}
}

func TestHandshake_WrongPeerStaticFails(t *testing.T) {
	server, client, prologue := handshakePeers(t, SuiteChaChaPoly)
	imposter, _ := GenerateIdentity()

	init, _ := NewInitiator(InitiatorConfig{
		Identity: server, PeerPublicKey: client.PublicKey(),
		Suite: SuiteChaChaPoly, Prologue: prologue, PSK: SentinelPSK(),
	})
	// Client expects a different server identity than the one connecting.
	resp, _ := NewResponder(ResponderConfig{
		Identity: client, PeerPublicKey: imposter.PublicKey(),
		Suite: SuiteChaChaPoly, Prologue: prologue, SelectPSK: sentinelSelector,
	})

	msg1, err := init.Message1(SentinelPSK().ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := resp.Accept(msg1); err == nil {
		t.Error("handshake with wrong peer static key succeeded, want failure")
	}
}

func TestSession_ReplayAndTamperFail(t *testing.T) {
	serverSess, clientSess := runHandshake(t, SuiteChaChaPoly, SentinelPSK(), sentinelSelector)

	ct, err := serverSess.Encrypt([]byte("once"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientSess.Decrypt(ct); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}
	if _, err := clientSess.Decrypt(ct); err == nil {
		t.Error("replayed ciphertext decrypted, want AEAD failure")
	}

	ct2, _ := serverSess.Encrypt([]byte("tamper me"))
	ct2[len(ct2)-1] ^= 0x01
	if _, err := clientSess.Decrypt(ct2); err == nil {
		t.Error("tampered ciphertext decrypted, want AEAD failure")
	}
}

func TestSession_EncryptSizeLimit(t *testing.T) {
	serverSess, _ := runHandshake(t, SuiteChaChaPoly, SentinelPSK(), sentinelSelector)

	if _, err := serverSess.Encrypt(make([]byte, MaxTransportPlaintext)); err != nil {
		t.Errorf("plaintext at the limit rejected: %v", err)
	}
	if _, err := serverSess.Encrypt(make([]byte, MaxTransportPlaintext+1)); err == nil {
		t.Error("oversized plaintext accepted, want error")
	}
}

func TestNoiseHandshakeEnvelope_RoundTrip(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xfe, 0xff}
	env, err := EncodeNoiseHandshake(raw)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseNoiseHandshake(env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, raw) {
		t.Errorf("round trip = %x, want %x", back, raw)
	}
}

func TestInitMessages_Validate(t *testing.T) {
	id, _ := GenerateIdentity()

	if _, err := EncodeClientInit(ClientInit{ClientID: "bogus", Version: 1, Suite: SuiteChaChaPoly}); err == nil {
		t.Error("bad client_id accepted")
	}
	if _, err := EncodeClientInit(ClientInit{ClientID: id.ID(), Version: 2, Suite: SuiteChaChaPoly}); err == nil {
		t.Error("bad version accepted")
	}
	if _, err := EncodeClientInit(ClientInit{ClientID: id.ID(), Version: 1, Suite: "25519_DES_MD5"}); err == nil {
		t.Error("bad suite accepted")
	}

	raw, err := EncodeClientInit(ClientInit{ClientID: id.ID(), Version: 1, Suite: SuiteAESGCM})
	if err != nil {
		t.Fatal(err)
	}
	ci, err := ParseClientInit(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ci.ClientID != id.ID() || ci.Suite != SuiteAESGCM {
		t.Errorf("round trip mismatch: %+v", ci)
	}

	if _, err := ParseServerInit(raw); err == nil {
		t.Error("client/init accepted as server/init")
	}
}
