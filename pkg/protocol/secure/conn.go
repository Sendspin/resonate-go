// ABOUTME: The encrypted WebSocket connection — drives the init/noise preamble
// ABOUTME: from either side and frames all subsequent traffic through the Session.
package secure

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// DefaultHandshakeTimeout bounds each expected message during the preamble,
// per the spec's failure-handling recommendation.
const DefaultHandshakeTimeout = 30 * time.Second

// handshakeReadLimit caps preamble frame sizes; init and noise messages are
// all well under this.
const handshakeReadLimit = 64 << 10

// Conn is an established encrypted Sendspin connection. All traffic after the
// preamble travels as Noise-encrypted binary WebSocket frames; JSON control
// messages are transport type 0. Reads must come from a single goroutine;
// writes are internally serialized.
type Conn struct {
	ws      *websocket.Conn
	sess    *Session
	reasm   *Reassembler
	writeMu sync.Mutex
	peerID  string

	// Retained for in-band re-handshakes: client_id/server_id and suite
	// carry over, and the new prologue is the prior handshake's hash.
	identity *Identity
	peerPub  []byte
	suite    Suite
}

// ServerHandshakeConfig configures the server side of the preamble. The
// server is the Noise initiator regardless of which side dialed.
type ServerHandshakeConfig struct {
	Identity *Identity
	// SelectPSK returns the PSK to mix for this client — pairing-record
	// lookup in a real server. Nil selects the Sentinel PSK for every
	// client (unpaired-access only).
	SelectPSK func(clientID string) (PSK, error)
	// HandshakeTimeout bounds each expected preamble message; 0 selects
	// DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// MaxMessageSize bounds reassembled message sizes post-handshake; 0
	// selects DefaultMaxMessageSize.
	MaxMessageSize int
}

// ServerHandshake performs the server side of the connection preamble:
// read client/init, send server/init, send Noise message 1, read Noise
// message 2, switch to transport mode. On any failure the socket is closed
// without an application-level error, per spec.
func ServerHandshake(ws *websocket.Conn, cfg ServerHandshakeConfig) (conn *Conn, ci ClientInit, err error) {
	defer func() {
		if err != nil {
			ws.Close()
		}
	}()
	if cfg.Identity == nil {
		return nil, ClientInit{}, fmt.Errorf("server handshake requires an identity")
	}
	timeout := cfg.HandshakeTimeout
	if timeout == 0 {
		timeout = DefaultHandshakeTimeout
	}
	ws.SetReadLimit(handshakeReadLimit)

	clientInitRaw, err := readTextFrame(ws, timeout)
	if err != nil {
		return nil, ClientInit{}, fmt.Errorf("read client/init: %w", err)
	}
	ci, err = ParseClientInit(clientInitRaw)
	if err != nil {
		return nil, ClientInit{}, err
	}
	clientPub, err := ParseID(ci.ClientID)
	if err != nil {
		return nil, ClientInit{}, err
	}

	serverInitRaw, err := EncodeServerInit(ServerInit{ServerID: cfg.Identity.ID(), Version: CoreVersion})
	if err != nil {
		return nil, ClientInit{}, err
	}
	if err = writeTextFrame(ws, serverInitRaw, timeout); err != nil {
		return nil, ClientInit{}, fmt.Errorf("write server/init: %w", err)
	}

	psk := SentinelPSK()
	if cfg.SelectPSK != nil {
		psk, err = cfg.SelectPSK(ci.ClientID)
		if err != nil {
			return nil, ClientInit{}, fmt.Errorf("select psk: %w", err)
		}
	}

	init, err := NewInitiator(InitiatorConfig{
		Identity:      cfg.Identity,
		PeerPublicKey: clientPub,
		Suite:         ci.Suite,
		Prologue:      Prologue(clientInitRaw, serverInitRaw),
		PSK:           psk,
	})
	if err != nil {
		return nil, ClientInit{}, err
	}
	msg1, err := init.Message1(psk.ID())
	if err != nil {
		return nil, ClientInit{}, err
	}
	msg1Env, err := EncodeNoiseHandshake(msg1)
	if err != nil {
		return nil, ClientInit{}, err
	}
	if err = writeTextFrame(ws, msg1Env, timeout); err != nil {
		return nil, ClientInit{}, fmt.Errorf("write noise message 1: %w", err)
	}

	msg2Env, err := readTextFrame(ws, timeout)
	if err != nil {
		return nil, ClientInit{}, fmt.Errorf("read noise message 2: %w", err)
	}
	msg2, err := ParseNoiseHandshake(msg2Env)
	if err != nil {
		return nil, ClientInit{}, err
	}
	sess, err := init.Finish(msg2)
	if err != nil {
		return nil, ClientInit{}, err
	}

	c := newConn(ws, sess, ci.ClientID, cfg.MaxMessageSize)
	c.identity, c.peerPub, c.suite = cfg.Identity, clientPub, ci.Suite
	return c, ci, nil
}

// ClientHandshakeConfig configures the client side of the preamble.
type ClientHandshakeConfig struct {
	Identity *Identity
	// ExpectedServerID pins the server identity (stored-pubkey model). Empty
	// accepts the server/init identity at face value (shared-PSK model).
	ExpectedServerID string
	// Suite is the cipher suite to announce; empty selects SuiteChaChaPoly.
	Suite Suite
	// SelectPSK maps the psk_id from Noise message 1 to a candidate PSK.
	// Nil accepts only the Sentinel PSK.
	SelectPSK func(pskID string) (PSK, bool)
	// HandshakeTimeout bounds each expected preamble message; 0 selects
	// DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// MaxMessageSize bounds reassembled message sizes post-handshake; 0
	// selects DefaultMaxMessageSize.
	MaxMessageSize int
}

// ClientHandshake performs the client side of the connection preamble:
// send client/init, read server/init, respond to the Noise handshake, switch
// to transport mode. On any failure the socket is closed without an
// application-level error, per spec.
func ClientHandshake(ws *websocket.Conn, cfg ClientHandshakeConfig) (conn *Conn, si ServerInit, err error) {
	defer func() {
		if err != nil {
			ws.Close()
		}
	}()
	if cfg.Identity == nil {
		return nil, ServerInit{}, fmt.Errorf("client handshake requires an identity")
	}
	suite := cfg.Suite
	if suite == "" {
		suite = SuiteChaChaPoly
	}
	selectPSK := cfg.SelectPSK
	if selectPSK == nil {
		selectPSK = func(pskID string) (PSK, bool) {
			s := SentinelPSK()
			if pskID == s.ID() {
				return s, true
			}
			return PSK{}, false
		}
	}
	timeout := cfg.HandshakeTimeout
	if timeout == 0 {
		timeout = DefaultHandshakeTimeout
	}
	ws.SetReadLimit(handshakeReadLimit)

	clientInitRaw, err := EncodeClientInit(ClientInit{ClientID: cfg.Identity.ID(), Version: CoreVersion, Suite: suite})
	if err != nil {
		return nil, ServerInit{}, err
	}
	if err = writeTextFrame(ws, clientInitRaw, timeout); err != nil {
		return nil, ServerInit{}, fmt.Errorf("write client/init: %w", err)
	}

	serverInitRaw, err := readTextFrame(ws, timeout)
	if err != nil {
		return nil, ServerInit{}, fmt.Errorf("read server/init: %w", err)
	}
	si, err = ParseServerInit(serverInitRaw)
	if err != nil {
		return nil, ServerInit{}, err
	}
	if cfg.ExpectedServerID != "" && si.ServerID != cfg.ExpectedServerID {
		return nil, ServerInit{}, fmt.Errorf("server identity %q does not match expected %q", si.ServerID, cfg.ExpectedServerID)
	}
	serverPub, err := ParseID(si.ServerID)
	if err != nil {
		return nil, ServerInit{}, err
	}

	msg1Env, err := readTextFrame(ws, timeout)
	if err != nil {
		return nil, ServerInit{}, fmt.Errorf("read noise message 1: %w", err)
	}
	msg1, err := ParseNoiseHandshake(msg1Env)
	if err != nil {
		return nil, ServerInit{}, err
	}

	resp, err := NewResponder(ResponderConfig{
		Identity:      cfg.Identity,
		PeerPublicKey: serverPub,
		Suite:         suite,
		Prologue:      Prologue(clientInitRaw, serverInitRaw),
		SelectPSK:     selectPSK,
	})
	if err != nil {
		return nil, ServerInit{}, err
	}
	msg2, sess, err := resp.Accept(msg1)
	if err != nil {
		return nil, ServerInit{}, err
	}
	msg2Env, err := EncodeNoiseHandshake(msg2)
	if err != nil {
		return nil, ServerInit{}, err
	}
	if err = writeTextFrame(ws, msg2Env, timeout); err != nil {
		return nil, ServerInit{}, fmt.Errorf("write noise message 2: %w", err)
	}

	c := newConn(ws, sess, si.ServerID, cfg.MaxMessageSize)
	c.identity, c.peerPub, c.suite = cfg.Identity, serverPub, suite
	return c, si, nil
}

func newConn(ws *websocket.Conn, sess *Session, peerID string, maxMessageSize int) *Conn {
	// Transport frames are ciphertexts of at most maxNoiseMessage bytes.
	ws.SetReadLimit(maxNoiseMessage + 1024)
	ws.SetReadDeadline(time.Time{})
	return &Conn{
		ws:     ws,
		sess:   sess,
		reasm:  NewReassembler(maxMessageSize),
		peerID: peerID,
	}
}

// PeerID returns the peer's wire identity: the client_id on a server-side
// connection, the server_id on a client-side one.
func (c *Conn) PeerID() string { return c.peerID }

// HandshakeHash returns the Noise handshake hash h of this connection.
func (c *Conn) HandshakeHash() []byte { return c.sess.HandshakeHash() }

// WriteMessage encrypts and sends one message, fragmenting as needed.
func (c *Conn) WriteMessage(msgType byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	for _, frame := range Fragment(msgType, payload) {
		ct, err := c.sess.Encrypt(frame)
		if err != nil {
			return err
		}
		if err := c.ws.WriteMessage(websocket.BinaryMessage, ct); err != nil {
			return fmt.Errorf("write transport frame: %w", err)
		}
	}
	return nil
}

// WriteJSON marshals v and sends it as a JSON control message (type 0).
func (c *Conn) WriteJSON(v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal control message: %w", err)
	}
	return c.WriteMessage(MsgTypeJSON, body)
}

// ReadMessage receives the next complete message, decrypting and reassembling
// fragments. A text frame after transport mode, an AEAD failure, or a framing
// violation is terminal: the error is returned and the caller must close.
func (c *Conn) ReadMessage() (msgType byte, payload []byte, err error) {
	for {
		wsType, data, err := c.ws.ReadMessage()
		if err != nil {
			return 0, nil, err
		}
		if wsType != websocket.BinaryMessage {
			return 0, nil, fmt.Errorf("non-binary WebSocket frame in transport mode")
		}
		pt, err := c.sess.Decrypt(data)
		if err != nil {
			return 0, nil, err
		}
		msgType, payload, done, err := c.reasm.Feed(pt)
		if err != nil {
			return 0, nil, err
		}
		if done {
			return msgType, payload, nil
		}
	}
}

// Close closes the underlying WebSocket.
func (c *Conn) Close() error { return c.ws.Close() }

func readTextFrame(ws *websocket.Conn, timeout time.Duration) ([]byte, error) {
	if err := ws.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	msgType, data, err := ws.ReadMessage()
	if err != nil {
		return nil, err
	}
	if msgType != websocket.TextMessage {
		return nil, fmt.Errorf("expected text frame during handshake, got type %d", msgType)
	}
	return data, nil
}

func writeTextFrame(ws *websocket.Conn, data []byte, timeout time.Duration) error {
	if err := ws.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	return ws.WriteMessage(websocket.TextMessage, data)
}
