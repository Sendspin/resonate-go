// ABOUTME: Tests for identities and PSK machinery, anchored to the exact
// ABOUTME: constants published in the Sendspin spec's Encryption section.
package secure

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The spec publishes the Sentinel PSK and its psk_id as fixed values. If
// these tests fail, the derivation code cannot interoperate with any other
// implementation — do not "fix" the constants, fix the code.
const (
	specSentinelPSKHex   = "1b5e24dbc1aed95fc2a5a338a90c05df44bd10f5ec1f4cd66cbf86272767b9d3"
	specSentinelIDHex    = "185b15f6d2da4909bd1dc156a4ab206103abef0153bcd52d926170b95cf7ce8a"
	specSentinelIDBase64 = "GFsV9tLaSQm9HcFWpKsgYQOr7wFTvNUtkmFwuVz3zoo"
)

func TestSentinelPSK_MatchesSpecConstant(t *testing.T) {
	got := SentinelPSK()
	if hex.EncodeToString(got[:]) != specSentinelPSKHex {
		t.Errorf("SentinelPSK() = %x, spec says %s", got[:], specSentinelPSKHex)
	}
}

func TestSentinelPSKID_MatchesSpecConstant(t *testing.T) {
	got := SentinelPSK().ID()
	if got != specSentinelIDBase64 {
		t.Errorf("SentinelPSK().ID() = %q, spec says %q", got, specSentinelIDBase64)
	}

	raw, err := b64.DecodeString(got)
	if err != nil {
		t.Fatalf("psk_id is not valid base64url: %v", err)
	}
	if hex.EncodeToString(raw) != specSentinelIDHex {
		t.Errorf("psk_id bytes = %x, spec says %s", raw, specSentinelIDHex)
	}
}

func TestPSK_RoundTrip(t *testing.T) {
	p, err := NewPSK()
	if err != nil {
		t.Fatalf("NewPSK: %v", err)
	}
	enc := p.String()
	if len(enc) != IDLength {
		t.Errorf("encoded PSK length = %d, want %d", len(enc), IDLength)
	}
	back, err := ParsePSK(enc)
	if err != nil {
		t.Fatalf("ParsePSK: %v", err)
	}
	if back != p {
		t.Error("ParsePSK(String()) does not round-trip")
	}
}

func TestParsePSK_Rejects(t *testing.T) {
	cases := []string{
		"",
		"short",
		"GFsV9tLaSQm9HcFWpKsgYQOr7wFTvNUtkmFwuVz3zo",   // 42 chars
		"GFsV9tLaSQm9HcFWpKsgYQOr7wFTvNUtkmFwuVz3zooo", // 44 chars
		"GFsV9tLaSQm9HcFWpKsgYQOr7wFTvNUtkmFwuVz3z+o",  // '+' is base64, not base64url
	}
	for _, c := range cases {
		if _, err := ParsePSK(c); err == nil {
			t.Errorf("ParsePSK(%q) accepted, want error", c)
		}
	}
}

func TestIdentity_IDShape(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	wire := id.ID()
	if len(wire) != IDLength {
		t.Errorf("ID length = %d, want %d", len(wire), IDLength)
	}
	raw, err := ParseID(wire)
	if err != nil {
		t.Fatalf("ParseID: %v", err)
	}
	pub := id.PublicKey()
	for i := range raw {
		if raw[i] != pub[i] {
			t.Fatal("ParseID(ID()) does not round-trip to the public key")
		}
	}
}

func TestIdentity_Distinct(t *testing.T) {
	a, _ := GenerateIdentity()
	b, _ := GenerateIdentity()
	if a.ID() == b.ID() {
		t.Error("two generated identities share an ID")
	}
}

func TestLoadOrGenerateIdentity_PersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "server-identity")

	first, err := LoadOrGenerateIdentity(path)
	if err != nil {
		t.Fatalf("first LoadOrGenerateIdentity: %v", err)
	}
	second, err := LoadOrGenerateIdentity(path)
	if err != nil {
		t.Fatalf("second LoadOrGenerateIdentity: %v", err)
	}
	if first.ID() != second.ID() {
		t.Errorf("identity not stable across reloads: %s != %s", first.ID(), second.ID())
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat identity file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("identity file mode = %o, want 600", perm)
		}
	}
}

func TestLoadOrGenerateIdentity_RejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-identity")
	if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateIdentity(path); err == nil {
		t.Error("corrupt identity file accepted, want error")
	}
}

func TestParseID_RejectsWrongLength(t *testing.T) {
	if _, err := ParseID("tooshort"); err == nil {
		t.Error("short ID accepted, want error")
	}
}
