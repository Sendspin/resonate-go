// ABOUTME: Server connection front door — resolves the pairing PSK during the
// ABOUTME: handshake and establishes a playback session at the right trust.
package session

import (
	"fmt"
	"time"

	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
	"github.com/gorilla/websocket"
)

// PairingStore resolves the PSK to mix for a connecting client and its
// category, per the spec's server-side order (long-term record → staged
// Pairing PSK → Sentinel). MemoryPairingStore implements it.
type PairingStore interface {
	Resolve(clientID string) (secure.PSK, PSKCategory)
}

// ServerAcceptConfig configures the non-pairing accept path.
type ServerAcceptConfig struct {
	// Identity is the server's static keypair.
	Identity *secure.Identity
	// ServerName is the friendly name sent in server/hello.
	ServerName string
	// Store resolves the per-client PSK and category. Nil means no records:
	// every client matches the Sentinel PSK.
	Store PairingStore
	// AllowUnpairedPlayback grants a Sentinel-keyed client the 'playback'
	// activity when it advertises unpaired_access.enabled. When false, such a
	// client is offered no playback activity (it will typically disconnect
	// with pairing_required unless the operator moves it into pairing).
	AllowUnpairedPlayback bool
	// ChooseActiveRoles overrides the default role-activation policy.
	ChooseActiveRoles func(hello ClientHello) []string
	// HandshakeTimeout bounds each preamble message; 0 uses the secure
	// package default.
	HandshakeTimeout time.Duration
}

// AcceptResult is an accepted, established server connection.
type AcceptResult struct {
	Session     *ServerSession
	PSKCategory PSKCategory
	// TrustUser is true when the matched PSK is a long-term record.
	TrustUser bool
}

// AcceptServer performs the full server-side front door on an upgraded
// WebSocket: the Noise handshake with pairing-store PSK resolution, then
// session establishment with activities chosen from the matched PSK category.
// It handles the non-pairing paths (paired playback, unpaired-access
// playback); driving a pairing attempt is the operator-triggered path via the
// pairing helpers, not this function.
func AcceptServer(ws *websocket.Conn, cfg ServerAcceptConfig) (*AcceptResult, error) {
	if cfg.Identity == nil {
		return nil, fmt.Errorf("AcceptServer requires an identity")
	}

	// Capture the matched category from the PSK resolver: the handshake
	// selects the PSK by client_id, and we need its category afterward to
	// decide the activity set.
	category := PSKSentinel
	selectPSK := func(clientID string) (secure.PSK, error) {
		if cfg.Store == nil {
			category = PSKSentinel
			return secure.SentinelPSK(), nil
		}
		psk, cat := cfg.Store.Resolve(clientID)
		category = cat
		return psk, nil
	}

	conn, ci, err := secure.ServerHandshake(ws, secure.ServerHandshakeConfig{
		Identity:         cfg.Identity,
		SelectPSK:        selectPSK,
		HandshakeTimeout: cfg.HandshakeTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	_ = ci // client_id is available as conn.PeerID()

	// Choose activities from the matched category and the client's hello:
	//   long-term PSK           → playback (paired, user trust)
	//   sentinel + server allows + client advertised unpaired_access → playback
	//   otherwise               → no activity (client sends pairing_required
	//                             unless the operator moves it into pairing)
	// Pairing PSKs never reach this path (operator-triggered flow only).
	chooseActivities := func(hello ClientHello) []Activity {
		switch category {
		case PSKLongTerm:
			return []Activity{ActivityPlayback}
		case PSKSentinel:
			if cfg.AllowUnpairedPlayback && hello.UnpairedAccess.Enabled {
				return []Activity{ActivityPlayback}
			}
			return []Activity{}
		default:
			return []Activity{}
		}
	}

	sess, err := EstablishServer(conn, ServerConfig{
		ServerName:        cfg.ServerName,
		PSKCategory:       category,
		InitialActivities: []Activity{}, // overridden by ChooseActivities
		ChooseActivities:  chooseActivities,
		ChooseActiveRoles: cfg.ChooseActiveRoles,
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("establish: %w", err)
	}

	return &AcceptResult{
		Session:     sess,
		PSKCategory: category,
		TrustUser:   category == PSKLongTerm,
	}, nil
}
