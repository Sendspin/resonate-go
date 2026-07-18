// ABOUTME: PIN pairing flow choreography — dynamic and static PIN, both
// ABOUTME: sides, over the CPace primitives and re-handshake in pkg secure.
package session

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
)

// b64 is unpadded base64url, the encoding for every 32/48/64-byte pairing
// value carried on the wire.
var b64 = base64.RawURLEncoding

// Pair-abort reasons produced by the PIN flows.
const (
	AbortPINMismatch           = "pin_mismatch"
	AbortPINLengthUnacceptable = "pin_length_unacceptable"
	AbortAttemptTimeout        = "attempt_timeout"
	AbortUserCancelled         = "user_cancelled"
	AbortLockedOut             = "locked_out"
)

// PINPairingServerConfig configures the server side of a PIN pairing attempt.
type PINPairingServerConfig struct {
	// Method is dynamic_pin or static_pin (must match the SelectedPairMethod
	// of the pairing activate already sent by EstablishServer).
	Method string
	// PairingCounter is the number of pairing activates since the last Noise
	// handshake — the value EstablishServer used, fed into the CPace sid and
	// checked against the client's pairing_index.
	PairingCounter uint32
	// PINLength is the negotiated dynamic-PIN length to advertise in
	// server/pair-init. Ignored for static PIN.
	PINLength int
	// ProvidePIN returns the PIN the operator entered. For dynamic PIN it is
	// called after server/pair-init is sent (the client has emitted the PIN
	// for the operator to read); for static PIN it returns the device's
	// configured static PIN.
	ProvidePIN func() (string, error)
	// Persist stores the unwrapped long-term PSK for this client.
	Persist func(clientID string, psk secure.PSK) error
	// Resulting is the post-pairing session configuration (typically
	// playback at long-term trust). PSKCategory is forced to PSKLongTerm.
	Resulting ServerConfig
}

// CompletePINPairing runs the server side of a PIN pairing attempt on a
// session whose initial activate declared ['pairing'] with a PIN method. On
// success it persists the record, re-handshakes to the new PSK, and
// re-establishes the session. A pairing failure sends pair/abort and returns
// a *PairAbortError; the connection stays open for a retry.
func (s *ServerSession) CompletePINPairing(cfg PINPairingServerConfig) (*ServerSession, error) {
	dynamic := cfg.Method == PairMethodDynamicPIN
	h := s.Conn.HandshakeHash()

	// 1. client/pair-init: attempt start + (dynamic) commit_B.
	msg, err := readControl(s.Conn)
	if err != nil {
		return nil, fmt.Errorf("read client/pair-init: %w", err)
	}
	init, ok := msg.(*ClientPairInit)
	if !ok {
		if ab, isAbort := msg.(*PairAbort); isAbort {
			return nil, &PairAbortError{Reason: ab.Reason}
		}
		return nil, fmt.Errorf("expected client/pair-init, got %T", msg)
	}
	if uint32(init.PairingIndex) != cfg.PairingCounter {
		// A lower index is a leftover (silently discarded by spec); at this
		// synchronous entry point either way it is not our live attempt.
		return nil, fmt.Errorf("pairing_index %d does not match counter %d", init.PairingIndex, cfg.PairingCounter)
	}
	var commitB []byte
	if dynamic {
		if init.CommitB == "" {
			return nil, fmt.Errorf("dynamic pin: client/pair-init missing commit_B")
		}
		commitB, err = b64.DecodeString(init.CommitB)
		if err != nil {
			return nil, fmt.Errorf("decode commit_B: %w", err)
		}
	}

	// 2. (dynamic) server/pair-init: nonce_A + pin_length.
	var nonceA []byte
	if dynamic {
		nonceA = make([]byte, 32)
		if _, err := rand.Read(nonceA); err != nil {
			return nil, fmt.Errorf("sample nonce_A: %w", err)
		}
		if err := writeMessage(s.Conn, ServerPairInit{
			NonceA:    b64.EncodeToString(nonceA),
			PINLength: cfg.PINLength,
		}); err != nil {
			return nil, fmt.Errorf("send server/pair-init: %w", err)
		}
	}

	// The operator now enters the PIN (dynamic: read from the client's
	// out-channel; static: printed on the device).
	pin, err := cfg.ProvidePIN()
	if err != nil {
		_ = writeMessage(s.Conn, PairAbort{Reason: AbortUserCancelled})
		return nil, fmt.Errorf("obtain operator pin: %w", err)
	}

	// 3. CPace as initiator (role A). PRS is the typed PIN's ASCII digits.
	sid := secure.BuildPakeSID(h, cfg.PairingCounter)
	cp, err := secure.StartCPace(secure.CPaceInitiator, []byte(pin), sid, nil, secure.CPaceADServer)
	if err != nil {
		return nil, fmt.Errorf("start cpace: %w", err)
	}
	if err := writeMessage(s.Conn, ServerPairAuth{PakeMsg1: b64.EncodeToString(cp.PublicShare())}); err != nil {
		return nil, fmt.Errorf("send server/pair-auth: %w", err)
	}

	// 4. client/pair-auth: peer share.
	msg, err = readControl(s.Conn)
	if err != nil {
		return nil, fmt.Errorf("read client/pair-auth: %w", err)
	}
	auth, ok := msg.(*ClientPairAuth)
	if !ok {
		return nil, unexpectedOrAbort(msg, "client/pair-auth")
	}
	peerShare, err := b64.DecodeString(auth.PakeMsg2)
	if err != nil {
		return nil, fmt.Errorf("decode pake_msg_2: %w", err)
	}
	if err := cp.Derive(peerShare, secure.CPaceADClient); err != nil {
		return nil, fmt.Errorf("cpace derive: %w", err)
	}

	// 5. server/pair-confirm: our MCF tag.
	tag, err := cp.Tag()
	if err != nil {
		return nil, err
	}
	if err := writeMessage(s.Conn, ServerPairConfirm{ServerKC: b64.EncodeToString(tag)}); err != nil {
		return nil, fmt.Errorf("send server/pair-confirm: %w", err)
	}

	// 6. client/pair-confirm: peer tag + (dynamic) revealed nonce_B.
	msg, err = readControl(s.Conn)
	if err != nil {
		return nil, fmt.Errorf("read client/pair-confirm: %w", err)
	}
	confirm, ok := msg.(*ClientPairConfirm)
	if !ok {
		return nil, unexpectedOrAbort(msg, "client/pair-confirm")
	}
	peerTag, err := b64.DecodeString(confirm.ClientKC)
	if err != nil {
		return nil, fmt.Errorf("decode client_kc: %w", err)
	}

	// Verification order per spec: commit opening, key confirmation, PIN binding.
	if dynamic {
		nonceB, err := b64.DecodeString(confirm.NonceB)
		if err != nil {
			return nil, fmt.Errorf("decode nonce_B: %w", err)
		}
		if subtle.ConstantTimeCompare(secure.CommitB(nonceB), commitB) != 1 {
			// A revealed nonce that doesn't open the commit is a protocol
			// error: close without an application-level message.
			s.Conn.Close()
			return nil, fmt.Errorf("nonce_B does not open commit_B (protocol error)")
		}
		if !cp.Verify(peerTag) {
			return s.abortPIN(AbortPINMismatch)
		}
		if secure.DerivePIN(h, nonceA, nonceB, cfg.PINLength) != pin {
			return s.abortPIN(AbortPINMismatch)
		}
	} else if !cp.Verify(peerTag) {
		return s.abortPIN(AbortPINMismatch)
	}

	// 7. client/pair-finalize: wrapped PSK.
	msg, err = readControl(s.Conn)
	if err != nil {
		return nil, fmt.Errorf("read client/pair-finalize: %w", err)
	}
	fin, ok := msg.(*ClientPairFinalize)
	if !ok {
		return nil, unexpectedOrAbort(msg, "client/pair-finalize")
	}
	if fin.WrappedPSK == "" || fin.LongTermPSK != "" {
		return nil, fmt.Errorf("pin flow requires wrapped_psk (and only it)")
	}
	wrapped, err := b64.DecodeString(fin.WrappedPSK)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped_psk: %w", err)
	}
	isk, err := cp.ISK()
	if err != nil {
		return nil, err
	}
	psk, err := secure.UnwrapPSK(sid, isk, wrapped, s.Conn.Suite())
	if err != nil {
		// A wrapped_psk that fails to decrypt is a protocol error.
		s.Conn.Close()
		return nil, fmt.Errorf("unwrap psk (protocol error): %w", err)
	}
	if err := cfg.Persist(s.Conn.PeerID(), psk); err != nil {
		return nil, fmt.Errorf("persist pairing record: %w", err)
	}

	// 8. server/pair-finalize, then re-handshake to the new PSK and
	// re-establish the session at long-term trust.
	if err := writeMessage(s.Conn, ServerPairFinalize{}); err != nil {
		return nil, fmt.Errorf("send server/pair-finalize: %w", err)
	}
	if err := s.Conn.RehandshakeInitiate(psk); err != nil {
		return nil, fmt.Errorf("re-handshake to paired psk: %w", err)
	}
	cfg.Resulting.PSKCategory = PSKLongTerm
	return EstablishServer(s.Conn, cfg.Resulting)
}

func (s *ServerSession) abortPIN(reason string) (*ServerSession, error) {
	_ = writeMessage(s.Conn, PairAbort{Reason: reason})
	return nil, &PairAbortError{Reason: reason}
}

func unexpectedOrAbort(msg any, want string) error {
	if ab, ok := msg.(*PairAbort); ok {
		return &PairAbortError{Reason: ab.Reason}
	}
	return fmt.Errorf("expected %s, got %T", want, msg)
}

// PINPairingClientConfig configures the client side of a PIN pairing attempt.
type PINPairingClientConfig struct {
	// Method is dynamic_pin or static_pin.
	Method string
	// PairingCounter mirrors the server's counter (from the activate that
	// opened this attempt); used for the pairing_index and CPace sid.
	PairingCounter uint32
	// MinPINLength is the client's floor; a server pin_length below it (or
	// outside 4–12) aborts the attempt.
	MinPINLength int
	// StaticPIN is the device's printed PIN (static method only).
	StaticPIN string
	// EmitPIN receives the derived dynamic PIN for the operator to read
	// (dynamic method only).
	EmitPIN func(pin string)
	// NewPSK mints the long-term PSK to deliver; nil generates a random one.
	NewPSK func() (secure.PSK, error)
	// Persist stores the delivered PSK locally against the server_id.
	Persist func(serverID string, psk secure.PSK) error
	// ResultingHello is the client/hello for the re-established session; it
	// must re-assert trust_level 'user'.
	ResultingHello ClientHello
}

// RunPINPairing runs the client side of a PIN pairing attempt on a session
// whose activate selected a PIN method. On success it persists the record,
// responds to the server's re-handshake, and re-establishes the session at
// user trust. A local check failure sends pair/abort and returns a
// *PairAbortError.
func (s *ClientSession) RunPINPairing(cfg PINPairingClientConfig) (*ClientSession, error) {
	dynamic := cfg.Method == PairMethodDynamicPIN
	h := s.Conn.HandshakeHash()

	// 1. client/pair-init.
	var nonceB []byte
	init := ClientPairInit{PairingIndex: int(cfg.PairingCounter)}
	if dynamic {
		nonceB = make([]byte, 32)
		if _, err := rand.Read(nonceB); err != nil {
			return nil, fmt.Errorf("sample nonce_B: %w", err)
		}
		init.CommitB = b64.EncodeToString(secure.CommitB(nonceB))
	}
	if err := writeMessage(s.Conn, init); err != nil {
		return nil, fmt.Errorf("send client/pair-init: %w", err)
	}

	pin := cfg.StaticPIN

	// 2. (dynamic) server/pair-init: nonce_A + pin_length → derive & emit PIN.
	var nonceA []byte
	if dynamic {
		msg, err := readControl(s.Conn)
		if err != nil {
			return nil, fmt.Errorf("read server/pair-init: %w", err)
		}
		spi, ok := msg.(*ServerPairInit)
		if !ok {
			return nil, unexpectedOrAbort(msg, "server/pair-init")
		}
		if spi.PINLength < cfg.MinPINLength || spi.PINLength > 12 {
			return s.abortPINClient(AbortPINLengthUnacceptable)
		}
		nonceA, err = b64.DecodeString(spi.NonceA)
		if err != nil {
			return nil, fmt.Errorf("decode nonce_A: %w", err)
		}
		pin = secure.DerivePIN(h, nonceA, nonceB, spi.PINLength)
		if cfg.EmitPIN != nil {
			cfg.EmitPIN(pin)
		}
	}

	// 3. server/pair-auth → CPace as responder (role B).
	msg, err := readControl(s.Conn)
	if err != nil {
		return nil, fmt.Errorf("read server/pair-auth: %w", err)
	}
	spa, ok := msg.(*ServerPairAuth)
	if !ok {
		return nil, unexpectedOrAbort(msg, "server/pair-auth")
	}
	serverShare, err := b64.DecodeString(spa.PakeMsg1)
	if err != nil {
		return nil, fmt.Errorf("decode pake_msg_1: %w", err)
	}
	sid := secure.BuildPakeSID(h, cfg.PairingCounter)
	cp, err := secure.StartCPace(secure.CPaceResponder, []byte(pin), sid, nil, secure.CPaceADClient)
	if err != nil {
		return nil, fmt.Errorf("start cpace: %w", err)
	}
	if err := cp.Derive(serverShare, secure.CPaceADServer); err != nil {
		return nil, fmt.Errorf("cpace derive: %w", err)
	}
	if err := writeMessage(s.Conn, ClientPairAuth{PakeMsg2: b64.EncodeToString(cp.PublicShare())}); err != nil {
		return nil, fmt.Errorf("send client/pair-auth: %w", err)
	}

	// 4. server/pair-confirm → verify server tag.
	msg, err = readControl(s.Conn)
	if err != nil {
		return nil, fmt.Errorf("read server/pair-confirm: %w", err)
	}
	spc, ok := msg.(*ServerPairConfirm)
	if !ok {
		return nil, unexpectedOrAbort(msg, "server/pair-confirm")
	}
	serverTag, err := b64.DecodeString(spc.ServerKC)
	if err != nil {
		return nil, fmt.Errorf("decode server_kc: %w", err)
	}
	if !cp.Verify(serverTag) {
		return s.abortPINClient(AbortPINMismatch)
	}

	// 5. client/pair-confirm + client/pair-finalize (back to back).
	confirm := ClientPairConfirm{ClientKC: b64.EncodeToString(mustTag(cp))}
	if dynamic {
		confirm.NonceB = b64.EncodeToString(nonceB)
	}
	if err := writeMessage(s.Conn, confirm); err != nil {
		return nil, fmt.Errorf("send client/pair-confirm: %w", err)
	}

	newPSK := secure.SentinelPSK() // placeholder; replaced below
	if cfg.NewPSK != nil {
		newPSK, err = cfg.NewPSK()
	} else {
		newPSK, err = secure.NewPSK()
	}
	if err != nil {
		return nil, fmt.Errorf("mint long-term psk: %w", err)
	}
	isk, err := cp.ISK()
	if err != nil {
		return nil, err
	}
	wrapped, err := secure.WrapPSK(sid, isk, newPSK, s.Conn.Suite())
	if err != nil {
		return nil, fmt.Errorf("wrap psk: %w", err)
	}
	if err := writeMessage(s.Conn, ClientPairFinalize{WrappedPSK: b64.EncodeToString(wrapped)}); err != nil {
		return nil, fmt.Errorf("send client/pair-finalize: %w", err)
	}

	// 6. server/pair-finalize → persist, respond to re-handshake, re-establish.
	msg, err = readControl(s.Conn)
	if err != nil {
		return nil, fmt.Errorf("read server/pair-finalize: %w", err)
	}
	if ab, isAbort := msg.(*PairAbort); isAbort {
		return nil, &PairAbortError{Reason: ab.Reason}
	}
	if _, ok := msg.(*ServerPairFinalize); !ok {
		return nil, fmt.Errorf("expected server/pair-finalize, got %T", msg)
	}
	if err := cfg.Persist(s.Conn.PeerID(), newPSK); err != nil {
		return nil, fmt.Errorf("persist pairing record: %w", err)
	}

	mt, payload, err := s.Conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read rehandshake message 1: %w", err)
	}
	if mt != secure.MsgTypeJSON || !isNoiseHandshake(payload) {
		return nil, fmt.Errorf("expected noise/handshake after pairing, got type %d", mt)
	}
	if err := s.Conn.RehandshakeRespond(payload, func(pskID string) (secure.PSK, bool) {
		if pskID == newPSK.ID() {
			return newPSK, true
		}
		return secure.PSK{}, false
	}); err != nil {
		return nil, fmt.Errorf("re-handshake to paired psk: %w", err)
	}
	return EstablishClient(s.Conn, ClientConfig{Hello: cfg.ResultingHello, PSKCategory: PSKLongTerm})
}

func (s *ClientSession) abortPINClient(reason string) (*ClientSession, error) {
	_ = writeMessage(s.Conn, PairAbort{Reason: reason})
	return nil, &PairAbortError{Reason: reason}
}

func mustTag(cp *secure.CPace) []byte {
	tag, _ := cp.Tag()
	return tag
}
