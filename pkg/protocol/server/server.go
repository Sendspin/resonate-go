// ABOUTME: The listening spec-v2 server — accepts connections, syncs clocks,
// ABOUTME: and runs the per-connection message loop over sessions and groups.
package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Sendspin/sendspin-go/pkg/protocol/playback"
	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
	"github.com/Sendspin/sendspin-go/pkg/protocol/session"
	"github.com/gorilla/websocket"
)

// Config configures a Server.
type Config struct {
	// Identity is the server's static Noise keypair.
	Identity *secure.Identity
	// ServerName is the friendly name sent in server/hello.
	ServerName string
	// Store resolves each client's PSK and category. Nil means every client
	// matches the Sentinel PSK (unpaired access only).
	Store session.PairingStore
	// AllowUnpairedPlayback grants a Sentinel-keyed client playback when it
	// advertises unpaired_access.enabled.
	AllowUnpairedPlayback bool
	// ChooseActiveRoles overrides the default role-activation policy.
	ChooseActiveRoles func(hello session.ClientHello) []string
	// SourceKind is the source kind of the groups this server creates.
	SourceKind playback.SourceKind
	// Clock returns the server clock in microseconds; it must be monotonic
	// across the process. Nil installs a monotonic clock counting from the
	// server's creation.
	Clock func() int64
	// NextGroupID mints group ids; nil uses a random generator.
	NextGroupID func() string
	// HandshakeTimeout bounds each handshake preamble message; 0 uses the
	// secure package default.
	HandshakeTimeout time.Duration
}

// Server accepts encrypted Sendspin connections and runs each one's session:
// the handshake and establishment via AcceptServer, placement into a playback
// group, clock-sync replies, and client/state handling through the group
// manager. Driving audio into the groups is the audio loop's job (a separate
// concern that reads Groups()); this type owns the connection lifecycle.
type Server struct {
	cfg    Config
	clock  func() int64
	groups *session.GroupManager
}

// New builds a Server from cfg. It requires an identity.
func New(cfg Config) (*Server, error) {
	if cfg.Identity == nil {
		return nil, fmt.Errorf("server requires an identity")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = monotonicMicros()
	}
	gm := session.NewGroupManager(session.GroupManagerConfig{
		SourceKind:  cfg.SourceKind,
		NextGroupID: cfg.NextGroupID,
		Now:         clock,
	})
	return &Server{cfg: cfg, clock: clock, groups: gm}, nil
}

// Groups exposes the group manager so an audio loop can broadcast into the
// groups and callers can inspect membership and state.
func (s *Server) Groups() *session.GroupManager { return s.groups }

// Now returns the current server-clock time in microseconds.
func (s *Server) Now() int64 { return s.clock() }

// Handle runs the full lifecycle for one upgraded WebSocket: accept and
// establish the session, join the client into a solo group, then service its
// message loop until it departs. It returns nil on a graceful goodbye or a
// clean socket close, and the underlying error otherwise. The connection is
// always closed and the client removed from its group before returning.
func (s *Server) Handle(ws *websocket.Conn) error {
	res, err := session.AcceptServer(ws, session.ServerAcceptConfig{
		Identity:              s.cfg.Identity,
		ServerName:            s.cfg.ServerName,
		Store:                 s.cfg.Store,
		AllowUnpairedPlayback: s.cfg.AllowUnpairedPlayback,
		ChooseActiveRoles:     s.cfg.ChooseActiveRoles,
		HandshakeTimeout:      s.cfg.HandshakeTimeout,
	})
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	conn := res.Session.Conn
	clientID := conn.PeerID()

	// A newly-established client joins its own solo, stopped group with no
	// timing yet — the initial client/state refines it.
	if _, err := s.groups.Join(clientID, conn, playback.Timing{}, 0); err != nil {
		conn.Close()
		return fmt.Errorf("join: %w", err)
	}
	defer s.groups.Leave(clientID)
	defer conn.Close()

	return s.loop(conn, clientID)
}

// loop services one established connection until it ends.
func (s *Server) loop(conn *secure.Conn, clientID string) error {
	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			if isClose(err) {
				return nil
			}
			return err
		}
		if msgType != secure.MsgTypeJSON {
			// Players never send binary; ignore stray binary frames rather than
			// tearing the connection down. Source/visualizer input is a later
			// role's concern.
			continue
		}
		msg, err := session.Parse(payload)
		if err != nil {
			return fmt.Errorf("parse client message: %w", err)
		}
		switch v := msg.(type) {
		case *session.ClientTime:
			if err := s.answerTime(conn, *v); err != nil {
				return err
			}
		case *session.ClientState:
			if err := s.groups.ApplyClientState(clientID, *v); err != nil {
				return err
			}
		case *session.ClientGoodbye:
			return nil
		default:
			// Unknown or not-yet-handled control messages are skipped, matching
			// the protocol's message-level forward tolerance.
		}
	}
}

// answerTime replies to a client/time probe with server/time, stamping the
// receive time as early as possible and the transmit time at send.
func (s *Server) answerTime(conn *secure.Conn, ct session.ClientTime) error {
	received := s.clock()
	resp := session.ServerTime{
		ClientTransmitted: ct.ClientTransmitted,
		ServerReceived:    received,
		ServerTransmitted: s.clock(),
	}
	return writeControl(conn, resp)
}

func writeControl(conn *secure.Conn, v any) error {
	raw, err := session.Marshal(v)
	if err != nil {
		return err
	}
	return conn.WriteMessage(secure.MsgTypeJSON, raw)
}

// monotonicMicros returns a monotonic microsecond clock counting from now.
func monotonicMicros() func() int64 {
	start := time.Now()
	return func() int64 { return time.Since(start).Microseconds() }
}

// isClose reports whether err signals the peer simply went away — a WebSocket
// close frame or a closed underlying socket — rather than a protocol fault.
func isClose(err error) bool {
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		return true
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed)
}
