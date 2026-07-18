//go:build interop

// ABOUTME: Live interop test — this Go code acts as the Sendspin server and
// ABOUTME: dials the sendspin-dotnet InteropClient host over the encrypted path.
package secure

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Runs the .NET SDK's interop host (which listens and expects a server to
// dial in) and drives the unpaired scenario from this package's Conn:
// preamble → server/hello → client/hello → server/activate. Success is the
// host printing its "connected" and "success" events.
//
//	SENDSPIN_INTEROP_DOTNET=/path/to/sendspin-dotnet go test -tags interop -run TestInterop -v ./pkg/protocol/secure/
func TestInterop_GoServerAgainstDotnetHost(t *testing.T) {
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

	cmd := exec.Command("dotnet", "run",
		"--project", dotnetDir+"/tools/interop/InteropClient",
		"-c", "Release", "--", "unpaired", "8934")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

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

	ready := waitEvent("host_ready", 90*time.Second) // first dotnet run may compile
	port := int(ready["port"].(float64))
	dotnetClientID := ready["client_id"].(string)

	// --- The Go server side begins here. ---
	serverIdentity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ws, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("ws://127.0.0.1:%d/sendspin", port), nil)
	if err != nil {
		t.Fatalf("dial dotnet host: %v", err)
	}

	conn, ci, err := ServerHandshake(ws, ServerHandshakeConfig{Identity: serverIdentity})
	if err != nil {
		t.Fatalf("server handshake against dotnet host: %v", err)
	}
	defer conn.Close()
	if ci.ClientID != dotnetClientID {
		t.Errorf("client/init client_id %q != host_ready client_id %q", ci.ClientID, dotnetClientID)
	}
	t.Logf("noise handshake complete: suite=%s client=%s", ci.Suite, ci.ClientID)

	if err := conn.WriteJSON(map[string]any{
		"type":    "server/hello",
		"payload": map[string]any{"name": "go-interop-server"},
	}); err != nil {
		t.Fatalf("send server/hello: %v", err)
	}

	// Read until client/hello (ignoring anything else).
	var hello struct {
		Payload struct {
			Name           string   `json:"name"`
			SupportedRoles []string `json:"supported_roles"`
			UnpairedAccess struct {
				Enabled bool `json:"enabled"`
			} `json:"unpaired_access"`
		} `json:"payload"`
	}
	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read client/hello: %v", err)
		}
		if msgType != MsgTypeJSON {
			continue
		}
		var env struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(payload, &env) != nil || env.Type != "client/hello" {
			continue
		}
		if err := json.Unmarshal(payload, &hello); err != nil {
			t.Fatalf("parse client/hello: %v", err)
		}
		break
	}
	t.Logf("client/hello: name=%q roles=%v unpaired=%v",
		hello.Payload.Name, hello.Payload.SupportedRoles, hello.Payload.UnpairedAccess.Enabled)
	if !hello.Payload.UnpairedAccess.Enabled {
		t.Fatal("dotnet host did not advertise unpaired access in the unpaired scenario")
	}

	// Activate the first version of each role family the client offered.
	seen := map[string]bool{}
	var activeRoles []string
	for _, role := range hello.Payload.SupportedRoles {
		family, _, _ := strings.Cut(role, "@")
		if !seen[family] {
			seen[family] = true
			activeRoles = append(activeRoles, role)
		}
	}
	if activeRoles == nil {
		activeRoles = []string{}
	}
	if err := conn.WriteJSON(map[string]any{
		"type": "server/activate",
		"payload": map[string]any{
			"activities":   []string{"playback"},
			"active_roles": activeRoles,
		},
	}); err != nil {
		t.Fatalf("send server/activate: %v", err)
	}

	// Keep servicing the connection (the client starts client/time etc.)
	// while we wait for the host's verdict.
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	waitEvent("connected", 30*time.Second)
	waitEvent("success", 10*time.Second)
	t.Log("INTEROP PASS: go server ↔ dotnet client (unpaired)")
}
