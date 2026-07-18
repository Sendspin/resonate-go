//go:build interop

// ABOUTME: Live interop test — the typed session layer acts as the Sendspin
// ABOUTME: server against the sendspin-dotnet InteropClient host.
package session

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
	"github.com/gorilla/websocket"
)

// startDotnetHost spawns the sendspin-dotnet InteropClient for a scenario
// and returns an event channel plus a wait helper.
func startDotnetHost(t *testing.T, scenario, port string, extraArgs ...string) (chan map[string]any, func(name string, timeout time.Duration) map[string]any) {
	t.Helper()
	dotnetDir := os.Getenv("SENDSPIN_INTEROP_DOTNET")
	if dotnetDir == "" {
		dotnetDir = "/workspace/sendspin-dotnet"
	}
	if _, err := os.Stat(dotnetDir); err != nil {
		t.Skipf("sendspin-dotnet checkout not found at %s (set SENDSPIN_INTEROP_DOTNET)", dotnetDir)
	}
	if _, err := exec.LookPath("dotnet"); err != nil {
		t.Skip("dotnet SDK not on PATH")
	}

	args := append([]string{"run", "--project", dotnetDir + "/tools/interop/InteropClient", "-c", "Release", "--", scenario, port}, extraArgs...)
	cmd := exec.Command("dotnet", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	events := make(chan map[string]any, 32)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "{") {
				continue
			}
			var ev map[string]any
			if json.Unmarshal([]byte(line), &ev) == nil {
				t.Logf("dotnet host: %s", line)
				events <- ev
			}
		}
		close(events)
	}()
	waitEvent := func(name string, timeout time.Duration) map[string]any {
		deadline := time.After(timeout)
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					t.Fatalf("dotnet host exited before %q event", name)
				}
				if ev["event"] == name {
					return ev
				}
			case <-deadline:
				t.Fatalf("timed out waiting for %q event", name)
			}
		}
	}
	return events, waitEvent
}

// Drives the dotnet unpaired scenario end to end through EstablishServer:
// Noise preamble → server/hello → client/hello → server/activate, then waits
// for the host's "connected" and "success" verdicts.
//
//	SENDSPIN_INTEROP_DOTNET=/path/to/sendspin-dotnet go test -tags interop -run TestInterop -v ./pkg/protocol/session/
func TestInterop_SessionAgainstDotnetHost(t *testing.T) {
	_, waitEvent := startDotnetHost(t, "unpaired", "8935")
	ready := waitEvent("host_ready", 90*time.Second)
	port := int(ready["port"].(float64))

	serverIdentity, err := secure.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ws, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("ws://127.0.0.1:%d/sendspin", port), nil)
	if err != nil {
		t.Fatalf("dial dotnet host: %v", err)
	}
	conn, ci, err := secure.ServerHandshake(ws, secure.ServerHandshakeConfig{Identity: serverIdentity})
	if err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	defer conn.Close()
	t.Logf("noise handshake complete: suite=%s client=%s", ci.Suite, ci.ClientID)

	sess, err := EstablishServer(conn, ServerConfig{
		ServerName:        "go-session-interop",
		PSKCategory:       PSKSentinel,
		InitialActivities: []Activity{ActivityPlayback},
	})
	if err != nil {
		t.Fatalf("EstablishServer against dotnet host: %v", err)
	}
	t.Logf("session established: client=%q trust=%s roles=%v",
		sess.Hello.Name, sess.Hello.TrustLevel, sess.ActiveRoles)
	if !sess.Hello.UnpairedAccess.Enabled {
		t.Fatal("dotnet host did not advertise unpaired access")
	}
	if sess.Hello.TrustLevel != TrustNone {
		t.Errorf("trust level = %q, want none", sess.Hello.TrustLevel)
	}

	// Service the connection while awaiting the verdict.
	go func() {
		for {
			if _, _, err := sess.Conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	waitEvent("connected", 30*time.Second)
	waitEvent("success", 10*time.Second)
	t.Log("INTEROP PASS: go session layer ↔ dotnet client (unpaired)")
}

// Drives the dotnet pairing scenario: handshake on a shared Pairing PSK,
// pairing activate, client/pair-finalize → persist → server/pair-finalize,
// re-handshake to the delivered long-term PSK, and re-establishment at
// 'user' trust. The host verifies a LongTerm record bound to our server_id.
func TestInterop_PairingPSKAgainstDotnetHost(t *testing.T) {
	pairingPSK, err := secure.NewPSK()
	if err != nil {
		t.Fatal(err)
	}
	_, waitEvent := startDotnetHost(t, "pairing", "8936", fmt.Sprintf("%x", pairingPSK[:]))

	ready := waitEvent("host_ready", 90*time.Second)
	port := int(ready["port"].(float64))

	serverIdentity, err := secure.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ws, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("ws://127.0.0.1:%d/sendspin", port), nil)
	if err != nil {
		t.Fatalf("dial dotnet host: %v", err)
	}
	conn, ci, err := secure.ServerHandshake(ws, secure.ServerHandshakeConfig{
		Identity:  serverIdentity,
		SelectPSK: func(string) (secure.PSK, error) { return pairingPSK, nil },
	})
	if err != nil {
		t.Fatalf("server handshake on pairing psk: %v", err)
	}
	defer conn.Close()
	t.Logf("noise handshake on pairing psk: suite=%s client=%s", ci.Suite, ci.ClientID)

	sess, err := EstablishServer(conn, ServerConfig{
		ServerName:         "go-pairing-server",
		PSKCategory:        PSKPairing,
		InitialActivities:  []Activity{ActivityPairing},
		SelectedPairMethod: PairMethodPairingPSK,
	})
	if err != nil {
		t.Fatalf("EstablishServer (pairing): %v", err)
	}

	store := NewMemoryPairingStore()
	after, err := sess.CompletePairingPSK(store.PutRecord, ServerConfig{
		ServerName:        "go-pairing-server",
		InitialActivities: []Activity{ActivityPlayback},
	})
	if err != nil {
		t.Fatalf("CompletePairingPSK: %v", err)
	}
	records := store.Records()
	if len(records) != 1 || records[0].PeerID != ci.ClientID {
		t.Fatalf("server records after pairing = %+v", records)
	}
	t.Logf("post-pairing session: trust=%s roles=%v", after.Hello.TrustLevel, after.ActiveRoles)
	if after.Hello.TrustLevel != TrustUser {
		t.Errorf("post-pairing trust = %q, want user", after.Hello.TrustLevel)
	}

	go func() {
		for {
			if _, _, err := after.Conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ev := waitEvent("pairing_completed", 30*time.Second)
	if persisted, _ := ev["long_term_record_persisted"].(bool); !persisted {
		t.Error("dotnet host did not persist a long-term record")
	}
	if sid, _ := ev["server_id"].(string); sid != serverIdentity.ID() {
		t.Errorf("host paired with server_id %q, want %q", sid, serverIdentity.ID())
	}
	waitEvent("success", 10*time.Second)
	t.Log("INTEROP PASS: go server ↔ dotnet client (pairing_psk)")
}
