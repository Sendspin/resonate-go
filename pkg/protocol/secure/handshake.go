// ABOUTME: The KKpsk2 Noise handshake — server as initiator, client as
// ABOUTME: responder with psk_id-based PSK selection — and the transport Session.
package secure

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/flynn/noise"
)

// maxNoiseMessage is the Noise-spec cap on a single transport message.
const maxNoiseMessage = 65535

// aeadTagSize is the AEAD authentication tag size for both defined suites.
const aeadTagSize = 16

// MaxTransportPlaintext is the largest plaintext a single Noise transport
// message can carry (the framing layer's type byte counts against this).
const MaxTransportPlaintext = maxNoiseMessage - aeadTagSize

// msg1Payload is the JSON carried encrypted inside Noise message 1.
type msg1Payload struct {
	PSKID string `json:"psk_id"`
}

// InitiatorConfig configures the server side of the handshake. The server is
// always the Noise initiator, regardless of who opened the WebSocket.
type InitiatorConfig struct {
	Identity      *Identity
	PeerPublicKey []byte // client's static public key, from client/init's client_id
	Suite         Suite  // the suite the client picked in client/init
	Prologue      []byte // Prologue(clientInitRaw, serverInitRaw)
	PSK           PSK    // the PSK the server selected for this client
}

// Initiator drives Noise messages 1 and 2 from the server side.
type Initiator struct {
	hs *noise.HandshakeState
}

// NewInitiator prepares the server-side handshake state.
func NewInitiator(cfg InitiatorConfig) (*Initiator, error) {
	hs, err := newHandshakeState(cfg.Suite, cfg.Identity, cfg.PeerPublicKey, cfg.Prologue, cfg.PSK, true)
	if err != nil {
		return nil, err
	}
	return &Initiator{hs: hs}, nil
}

// Message1 produces Noise message 1, whose encrypted payload carries the
// psk_id so the responder can select the PSK before processing message 2.
func (i *Initiator) Message1(pskID string) ([]byte, error) {
	payload, err := json.Marshal(msg1Payload{PSKID: pskID})
	if err != nil {
		return nil, fmt.Errorf("marshal message 1 payload: %w", err)
	}
	msg, _, _, err := i.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, fmt.Errorf("write noise message 1: %w", err)
	}
	return msg, nil
}

// Finish processes Noise message 2 and returns the transport session.
func (i *Initiator) Finish(message2 []byte) (*Session, error) {
	_, csSend, csRecv, err := i.hs.ReadMessage(nil, message2)
	if err != nil {
		return nil, fmt.Errorf("read noise message 2: %w", err)
	}
	if csSend == nil || csRecv == nil {
		return nil, fmt.Errorf("handshake did not complete after message 2")
	}
	// Split() order: first CipherState encrypts initiator→responder.
	return newSession(csSend, csRecv, i.hs.ChannelBinding()), nil
}

// ResponderConfig configures the client side of the handshake.
type ResponderConfig struct {
	Identity      *Identity
	PeerPublicKey []byte // server's static public key, from server/init's server_id
	Suite         Suite
	Prologue      []byte
	// SelectPSK maps the psk_id from message 1 to a candidate PSK. Returning
	// false fails the handshake (spec: "If no candidate matches, the
	// handshake fails").
	SelectPSK func(pskID string) (PSK, bool)
}

// Responder handles Noise message 1 and produces message 2 on the client side.
type Responder struct {
	cfg ResponderConfig
}

// NewResponder prepares the client-side handshake.
func NewResponder(cfg ResponderConfig) (*Responder, error) {
	if cfg.SelectPSK == nil {
		return nil, fmt.Errorf("responder requires a SelectPSK callback")
	}
	return &Responder{cfg: cfg}, nil
}

// Accept processes Noise message 1, selects the PSK named by its psk_id
// payload, and returns Noise message 2 plus the transport session.
//
// psk2 placement means reading message 1 never touches the PSK value, but
// flynn/noise fixes the PSK at state creation. So: read message 1 with a
// throwaway state to learn the psk_id, then rebuild the state with the
// selected PSK and replay message 1 before writing message 2.
func (r *Responder) Accept(message1 []byte) (message2 []byte, sess *Session, err error) {
	probe, err := newHandshakeState(r.cfg.Suite, r.cfg.Identity, r.cfg.PeerPublicKey, r.cfg.Prologue, SentinelPSK(), false)
	if err != nil {
		return nil, nil, err
	}
	payload, _, _, err := probe.ReadMessage(nil, message1)
	if err != nil {
		return nil, nil, fmt.Errorf("read noise message 1: %w", err)
	}
	var m1 msg1Payload
	if err := json.Unmarshal(payload, &m1); err != nil {
		return nil, nil, fmt.Errorf("malformed message 1 payload: %w", err)
	}

	psk, ok := r.cfg.SelectPSK(m1.PSKID)
	if !ok {
		return nil, nil, fmt.Errorf("no candidate PSK matches psk_id %q", m1.PSKID)
	}

	hs, err := newHandshakeState(r.cfg.Suite, r.cfg.Identity, r.cfg.PeerPublicKey, r.cfg.Prologue, psk, false)
	if err != nil {
		return nil, nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, message1); err != nil {
		return nil, nil, fmt.Errorf("re-read noise message 1: %w", err)
	}

	// Message 2 payload is the empty JSON object per spec.
	msg2, csInit, csResp, err := hs.WriteMessage(nil, []byte("{}"))
	if err != nil {
		return nil, nil, fmt.Errorf("write noise message 2: %w", err)
	}
	if csInit == nil || csResp == nil {
		return nil, nil, fmt.Errorf("handshake did not complete after message 2")
	}
	// The responder sends with the second CipherState, receives with the first.
	return msg2, newSession(csResp, csInit, hs.ChannelBinding()), nil
}

func newHandshakeState(suite Suite, id *Identity, peerPub, prologue []byte, psk PSK, initiator bool) (*noise.HandshakeState, error) {
	if id == nil {
		return nil, fmt.Errorf("handshake requires an identity")
	}
	if len(peerPub) != KeySize {
		return nil, fmt.Errorf("peer public key must be %d bytes, got %d", KeySize, len(peerPub))
	}
	cs, err := suite.cipherSuite()
	if err != nil {
		return nil, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeKK,
		Initiator:   initiator,
		Prologue:    prologue,
		StaticKeypair: noise.DHKey{
			Private: id.PrivateKey(),
			Public:  id.PublicKey(),
		},
		PeerStatic:            peerPub,
		PresharedKey:          append([]byte(nil), psk[:]...),
		PresharedKeyPlacement: 2,
	})
	if err != nil {
		return nil, fmt.Errorf("init noise handshake: %w", err)
	}
	return hs, nil
}

// Session is an established Noise transport channel. Each direction has its
// own cipher state with a monotonic nonce, so replayed or reordered
// ciphertexts fail AEAD decryption. Not safe for concurrent use; the
// connection's writer and reader must each serialize access to their side.
type Session struct {
	send *noise.CipherState
	recv *noise.CipherState
	hash []byte
}

func newSession(send, recv *noise.CipherState, hash []byte) *Session {
	return &Session{send: send, recv: recv, hash: append([]byte(nil), hash...)}
}

// Encrypt seals one transport message. The plaintext (message-type byte
// included) must not exceed MaxTransportPlaintext; larger payloads must be
// fragmented by the framing layer before encryption.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxTransportPlaintext {
		return nil, fmt.Errorf("plaintext %d bytes exceeds max %d; fragment first", len(plaintext), MaxTransportPlaintext)
	}
	ct, err := s.send.Encrypt(nil, nil, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt transport message: %w", err)
	}
	return ct, nil
}

// Decrypt opens one transport message. Any AEAD failure is terminal for the
// connection per the spec's failure-handling rules.
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error) {
	pt, err := s.recv.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt transport message: %w", err)
	}
	return pt, nil
}

// HandshakeHash returns the Noise handshake hash h — the prologue for an
// in-band re-handshake and an input to pairing's PAKE session id.
func (s *Session) HandshakeHash() []byte {
	return append([]byte(nil), s.hash...)
}
