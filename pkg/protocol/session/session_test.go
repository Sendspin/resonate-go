// ABOUTME: Message-shape tests and full loopback session establishment over
// ABOUTME: the encrypted transport, including admissibility failure paths.
package session

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
	"github.com/gorilla/websocket"
)

func TestMarshal_WireShapes(t *testing.T) {
	raw, err := Marshal(ClientHello{
		Name:           "shape-test",
		TrustLevel:     TrustNone,
		SupportedRoles: []string{"player@v1"},
		PlayerSupport: &PlayerSupport{
			SupportedFormats:  []AudioFormat{{Codec: "opus", Channels: 2, SampleRate: 48000, BitDepth: 16}},
			BufferCapacity:    1 << 20,
			SupportedCommands: []string{"volume", "mute"},
		},
		UnpairedAccess: UnpairedAccess{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		`"type":"client/hello"`,
		`"trust_level":"none"`,
		`"player@v1_support"`,
		`"unpaired_access":{"enabled":true}`,
		`"buffer_capacity":1048576`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("client/hello wire form missing %s: %s", want, s)
		}
	}
	// Hard cutover: legacy field names must never appear.
	for _, banned := range []string{"player_support", "connection_reason", "client_id"} {
		if strings.Contains(s, `"`+banned+`"`) {
			t.Errorf("client/hello contains legacy field %q", banned)
		}
	}

	raw, err = Marshal(ServerActivate{Activities: []Activity{ActivityPlayback}, ActiveRoles: roles("player@v1")})
	if err != nil {
		t.Fatal(err)
	}
	if want := `"activities":["playback"],"active_roles":["player@v1"]`; !strings.Contains(string(raw), want) {
		t.Errorf("server/activate wire form missing %s: %s", want, raw)
	}

	// Omitted vs explicitly-empty active_roles must differ on the wire.
	raw, _ = Marshal(ServerActivate{Activities: []Activity{}})
	if strings.Contains(string(raw), "active_roles") {
		t.Errorf("omitted active_roles serialized: %s", raw)
	}
	raw, _ = Marshal(ServerActivate{Activities: []Activity{}, ActiveRoles: roles()})
	if !strings.Contains(string(raw), `"active_roles":[]`) {
		t.Errorf("explicit empty active_roles not serialized: %s", raw)
	}
}

func TestParse_RegistryAndUnknown(t *testing.T) {
	raw, _ := Marshal(ClientGoodbye{Reason: GoodbyeRestart})
	msg, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	gb, ok := msg.(*ClientGoodbye)
	if !ok || gb.Reason != GoodbyeRestart {
		t.Errorf("Parse(goodbye) = %#v", msg)
	}

	// Unknown message types surface as UnknownMessage, not errors.
	msg, err = Parse([]byte(`{"type":"x/unknown","payload":{"foo":"bar"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := msg.(UnknownMessage); !ok || u.Type != "x/unknown" {
		t.Errorf("Parse(unknown) = %#v", msg)
	}

	// Unknown fields inside known payloads are ignored (forward compat).
	msg, err = Parse([]byte(`{"type":"client/time","payload":{"client_transmitted":42,"future_field":true}}`))
	if err != nil {
		t.Fatalf("unknown field rejected: %v", err)
	}
	if ct := msg.(*ClientTime); ct.ClientTransmitted != 42 {
		t.Errorf("client/time = %+v", ct)
	}
}

// startSecureLoopback runs an httptest WebSocket endpoint performing the
// server-side handshake with the given PSK selector, delivering Conns on ch.
func startSecureLoopback(t *testing.T, serverID *secure.Identity, selectPSK func(string) (secure.PSK, error), ch chan<- *secure.Conn) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn, _, err := secure.ServerHandshake(ws, secure.ServerHandshakeConfig{Identity: serverID, SelectPSK: selectPSK})
		if err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		ch <- conn
	}))
	t.Cleanup(srv.Close)
	return srv
}

// dialSecure dials the loopback server and completes the client handshake.
func dialSecure(t *testing.T, srv *httptest.Server, clientID *secure.Identity, selectPSK func(string) (secure.PSK, bool)) *secure.Conn {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := secure.ClientHandshake(ws, secure.ClientHandshakeConfig{Identity: clientID, SelectPSK: selectPSK})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// loopback establishes a Sentinel-keyed encrypted connection pair.
func loopback(t *testing.T) (serverConn, clientConn *secure.Conn) {
	t.Helper()
	serverID, _ := secure.GenerateIdentity()
	clientID, _ := secure.GenerateIdentity()
	ch := make(chan *secure.Conn, 1)
	srv := startSecureLoopback(t, serverID, nil, ch)
	clientConn = dialSecure(t, srv, clientID, nil)
	return <-ch, clientConn
}

func testHello(unpaired bool) ClientHello {
	return ClientHello{
		Name:           "loop-client",
		TrustLevel:     TrustNone,
		SupportedRoles: []string{"player@v2", "player@v1", "metadata@v1"},
		UnpairedAccess: UnpairedAccess{Enabled: unpaired},
	}
}

func TestEstablish_Loopback(t *testing.T) {
	serverConn, clientConn := loopback(t)
	defer serverConn.Close()
	defer clientConn.Close()

	serverDone := make(chan *ServerSession, 1)
	go func() {
		sess, err := EstablishServer(serverConn, ServerConfig{
			ServerName:        "loop-server",
			PSKCategory:       PSKSentinel,
			InitialActivities: []Activity{ActivityPlayback},
		})
		if err != nil {
			t.Errorf("EstablishServer: %v", err)
			serverDone <- nil
			return
		}
		serverDone <- sess
	}()

	clientSess, err := EstablishClient(clientConn, ClientConfig{
		Hello:       testHello(true),
		PSKCategory: PSKSentinel,
	})
	if err != nil {
		t.Fatalf("EstablishClient: %v", err)
	}
	serverSess := <-serverDone
	if serverSess == nil {
		t.Fatal("server session failed")
	}

	if clientSess.ServerName != "loop-server" {
		t.Errorf("client saw server name %q", clientSess.ServerName)
	}
	if serverSess.Hello.Name != "loop-client" {
		t.Errorf("server saw client name %q", serverSess.Hello.Name)
	}
	// Default activation: first version per family, priority order kept.
	want := []string{"player@v2", "metadata@v1"}
	if len(serverSess.ActiveRoles) != 2 || serverSess.ActiveRoles[0] != want[0] || serverSess.ActiveRoles[1] != want[1] {
		t.Errorf("active roles = %v, want %v", serverSess.ActiveRoles, want)
	}
	if len(clientSess.ActiveRoles) != 2 || clientSess.ActiveRoles[0] != want[0] {
		t.Errorf("client active roles = %v, want %v", clientSess.ActiveRoles, want)
	}

	// Post-establishment traffic flows: goodbye round-trip.
	if err := clientSess.SendGoodbye(GoodbyeShutdown); err != nil {
		t.Fatal(err)
	}
	msgType, payload, err := serverSess.Conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if msgType != secure.MsgTypeJSON {
		t.Fatalf("goodbye arrived as type %d", msgType)
	}
	msg, err := Parse(payload)
	if err != nil {
		t.Fatal(err)
	}
	if gb, ok := msg.(*ClientGoodbye); !ok || gb.Reason != GoodbyeShutdown {
		t.Errorf("server received %#v", msg)
	}
}

func TestEstablish_InadmissibleActivateSendsGoodbye(t *testing.T) {
	serverConn, clientConn := loopback(t)
	defer serverConn.Close()
	defer clientConn.Close()

	// A misbehaving "server" that declares playback to a client without
	// unpaired access. EstablishServer refuses to do this (server-bug guard),
	// so drive the frames manually.
	goodbyeCh := make(chan any, 1)
	go func() {
		raw, _ := Marshal(ServerHello{Name: "rogue"})
		serverConn.WriteMessage(secure.MsgTypeJSON, raw)
		_, _, _ = serverConn.ReadMessage() // client/hello
		raw, _ = Marshal(ServerActivate{Activities: []Activity{ActivityPlayback}, ActiveRoles: roles()})
		serverConn.WriteMessage(secure.MsgTypeJSON, raw)
		_, payload, err := serverConn.ReadMessage()
		if err != nil {
			goodbyeCh <- err
			return
		}
		msg, _ := Parse(payload)
		goodbyeCh <- msg
	}()

	_, err := EstablishClient(clientConn, ClientConfig{
		Hello:       testHello(false), // unpaired access disabled
		PSKCategory: PSKSentinel,
	})
	admErr, ok := err.(*AdmissionError)
	if !ok {
		t.Fatalf("EstablishClient error = %v, want *AdmissionError", err)
	}
	if admErr.Verdict.Goodbye != GoodbyePairingRequired {
		t.Errorf("verdict = %+v, want pairing_required", admErr.Verdict)
	}

	got := <-goodbyeCh
	gb, ok := got.(*ClientGoodbye)
	if !ok || gb.Reason != GoodbyePairingRequired {
		t.Errorf("rogue server received %#v, want goodbye pairing_required", got)
	}
}

func TestEstablishServer_RefusesInadmissibleConfig(t *testing.T) {
	serverConn, clientConn := loopback(t)
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		// Client side: hello exchange so the server reaches the activate step.
		_, _, _ = clientConn.ReadMessage() // server/hello
		raw, _ := Marshal(testHello(false))
		clientConn.WriteMessage(secure.MsgTypeJSON, raw)
	}()

	_, err := EstablishServer(serverConn, ServerConfig{
		ServerName:        "guard",
		PSKCategory:       PSKSentinel,
		InitialActivities: []Activity{ActivityManagement}, // never valid on sentinel
	})
	if err == nil || !strings.Contains(err.Error(), "server bug") {
		t.Fatalf("EstablishServer = %v, want server-bug guard", err)
	}
}

func TestServerActivate_OmittedRolesRoundTrip(t *testing.T) {
	// nil pointer survives a marshal/parse cycle as nil; empty as empty.
	raw, _ := Marshal(ServerActivate{Activities: []Activity{}})
	msg, _ := Parse(raw)
	if act := msg.(*ServerActivate); act.ActiveRoles != nil {
		t.Errorf("omitted active_roles parsed as %#v", act.ActiveRoles)
	}
	raw, _ = Marshal(ServerActivate{Activities: []Activity{}, ActiveRoles: roles()})
	msg, _ = Parse(raw)
	act := msg.(*ServerActivate)
	if act.ActiveRoles == nil || len(*act.ActiveRoles) != 0 {
		t.Errorf("empty active_roles parsed as %#v", act.ActiveRoles)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
}
