// ABOUTME: Integration tests for the server accept front door — unpaired and
// ABOUTME: paired playback, plus a pair-then-reconnect round trip.
package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
	"github.com/gorilla/websocket"
)

// acceptHarness stands up a WebSocket endpoint whose handler runs AcceptServer
// with the given config and delivers each result on a channel.
func acceptHarness(t *testing.T, cfg ServerAcceptConfig) (*httptest.Server, <-chan *AcceptResult, <-chan error) {
	t.Helper()
	upgrader := websocket.Upgrader{}
	results := make(chan *AcceptResult, 1)
	errs := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		res, err := AcceptServer(ws, cfg)
		if err != nil {
			errs <- err
			return
		}
		results <- res
	}))
	t.Cleanup(srv.Close)
	return srv, results, errs
}

func dialClient(t *testing.T, srv *httptest.Server, id *secure.Identity, selectPSK func(string) (secure.PSK, bool)) *secure.Conn {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, _, err := secure.ClientHandshake(ws, secure.ClientHandshakeConfig{Identity: id, SelectPSK: selectPSK})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	return conn
}

func TestAccept_UnpairedPlayback(t *testing.T) {
	serverID, _ := secure.GenerateIdentity()
	clientID, _ := secure.GenerateIdentity()
	srv, results, errs := acceptHarness(t, ServerAcceptConfig{
		Identity:              serverID,
		ServerName:            "accept-server",
		AllowUnpairedPlayback: true,
	})

	conn := dialClient(t, srv, clientID, nil) // sentinel
	defer conn.Close()

	clientSess, err := EstablishClient(conn, ClientConfig{
		Hello:       testHello(true), // unpaired access enabled
		PSKCategory: PSKSentinel,
	})
	if err != nil {
		t.Fatalf("client establish: %v", err)
	}

	select {
	case err := <-errs:
		t.Fatalf("accept: %v", err)
	case res := <-results:
		if res.TrustUser {
			t.Error("unpaired connection reported user trust")
		}
		if len(res.Session.Activities) != 1 || res.Session.Activities[0] != ActivityPlayback {
			t.Errorf("activities = %v, want [playback]", res.Session.Activities)
		}
		if len(clientSess.ActiveRoles) == 0 {
			t.Error("client got no active roles")
		}
	}
}

func TestAccept_UnpairedDeniedWhenClientHasNoUnpairedAccess(t *testing.T) {
	serverID, _ := secure.GenerateIdentity()
	clientID, _ := secure.GenerateIdentity()
	srv, results, _ := acceptHarness(t, ServerAcceptConfig{
		Identity:              serverID,
		ServerName:            "accept-server",
		AllowUnpairedPlayback: true,
	})

	conn := dialClient(t, srv, clientID, nil)
	defer conn.Close()

	// Client did NOT advertise unpaired access → server declares no playback,
	// and the client rejects the empty-activity sentinel activation... actually
	// empty activities on sentinel are admissible, so the client accepts with
	// no roles. Assert the server granted no playback.
	clientSess, err := EstablishClient(conn, ClientConfig{
		Hello:       testHello(false),
		PSKCategory: PSKSentinel,
	})
	if err != nil {
		t.Fatalf("client establish: %v", err)
	}
	res := <-results
	if len(res.Session.Activities) != 0 {
		t.Errorf("activities = %v, want empty (no unpaired access)", res.Session.Activities)
	}
	if len(clientSess.ActiveRoles) != 0 {
		t.Errorf("client got roles %v without playback", clientSess.ActiveRoles)
	}
}

// The keystone integration test: a client pairs via Pairing PSK, then
// reconnects on its long-term record and the accept front door places it in a
// playback session at user trust — exercising the store, handshake PSK
// resolution, category→activity mapping, and establishment together.
func TestAccept_PairThenReconnectAsPaired(t *testing.T) {
	serverID, _ := secure.GenerateIdentity()
	clientID, _ := secure.GenerateIdentity()
	serverStore := NewMemoryPairingStore()
	clientStore := NewMemoryPairingStore()

	// --- Phase 1: pair via Pairing PSK. ---
	pairingPSK, _ := secure.NewPSK()
	serverStore.StagePairingPSK(clientID.ID(), pairingPSK)

	upgrader := websocket.Upgrader{}
	pairDone := make(chan error, 1)
	pairSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn, _, err := secure.ServerHandshake(ws, secure.ServerHandshakeConfig{
			Identity:  serverID,
			SelectPSK: func(string) (secure.PSK, error) { return pairingPSK, nil },
		})
		if err != nil {
			pairDone <- err
			return
		}
		sess, err := EstablishServer(conn, ServerConfig{
			ServerName: "accept-server", PSKCategory: PSKPairing,
			InitialActivities: []Activity{ActivityPairing}, SelectedPairMethod: PairMethodPairingPSK,
		})
		if err != nil {
			pairDone <- err
			return
		}
		_, err = sess.CompletePairingPSK(serverStore.PutRecord, ServerConfig{
			ServerName: "accept-server", InitialActivities: []Activity{ActivityPlayback},
		})
		pairDone <- err
	}))

	wsc, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(pairSrv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pconn, _, err := secure.ClientHandshake(wsc, secure.ClientHandshakeConfig{
		Identity: clientID,
		SelectPSK: func(id string) (secure.PSK, bool) {
			if id == pairingPSK.ID() {
				return pairingPSK, true
			}
			return secure.PSK{}, false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pairHello := testHello(false)
	pairHello.SupportedPairMethods = []PairMethodDescriptor{{Method: PairMethodPairingPSK}}
	cs, err := EstablishClient(pconn, ClientConfig{Hello: pairHello, PSKCategory: PSKPairing})
	if err != nil {
		t.Fatal(err)
	}
	longTerm, _ := secure.NewPSK()
	resultHello := testHello(false)
	resultHello.TrustLevel = TrustUser
	if _, err := cs.CompletePairingPSKClient(longTerm, clientStore.PutRecord, resultHello); err != nil {
		t.Fatalf("client pairing: %v", err)
	}
	if err := <-pairDone; err != nil {
		t.Fatalf("server pairing: %v", err)
	}
	pconn.Close()
	pairSrv.Close()

	// Both stores now hold the long-term record.
	if len(serverStore.Records()) != 1 || len(clientStore.Records()) != 1 {
		t.Fatalf("records after pairing: server=%d client=%d", len(serverStore.Records()), len(clientStore.Records()))
	}

	// --- Phase 2: reconnect through AcceptServer using the stored records. ---
	srv, results, errs := acceptHarness(t, ServerAcceptConfig{
		Identity:   serverID,
		ServerName: "accept-server",
		Store:      serverStore,
	})

	conn := dialClient(t, srv, clientID, func(pskID string) (secure.PSK, bool) {
		// Client resolves the server's psk_id against its own record.
		if pskID == longTerm.ID() {
			return longTerm, true
		}
		return secure.PSK{}, false
	})
	defer conn.Close()

	pairedHello := testHello(false)
	pairedHello.TrustLevel = TrustUser
	clientSess, err := EstablishClient(conn, ClientConfig{Hello: pairedHello, PSKCategory: PSKLongTerm})
	if err != nil {
		t.Fatalf("paired client establish: %v", err)
	}

	select {
	case err := <-errs:
		t.Fatalf("accept paired: %v", err)
	case res := <-results:
		if !res.TrustUser {
			t.Error("paired reconnect did not report user trust")
		}
		if res.PSKCategory != PSKLongTerm {
			t.Errorf("category = %v, want long-term", res.PSKCategory)
		}
		if len(res.Session.Activities) != 1 || res.Session.Activities[0] != ActivityPlayback {
			t.Errorf("activities = %v, want [playback]", res.Session.Activities)
		}
		if res.Session.Conn.PeerID() != clientID.ID() {
			t.Errorf("peer id = %q, want %q", res.Session.Conn.PeerID(), clientID.ID())
		}
		if len(clientSess.ActiveRoles) == 0 {
			t.Error("paired client got no roles")
		}
	}
}
