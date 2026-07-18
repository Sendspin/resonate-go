// ABOUTME: CPace tests — known-answer vectors shared with sendspin-dotnet and
// ABOUTME: aiosendspin, RFC 7748 X25519 checks, and confirmation failure modes.
package secure

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"golang.org/x/crypto/curve25519"
)

type cpaceKATs struct {
	CPace []struct {
		PRS, CI, SID, ADA, ADB string
		ScalarA, ScalarB       string
		Generator, Ya, Yb, ISK string
		Ta, Tb                 string
	} `json:"cpace"`
	Elligator2 []struct {
		R, X string
	} `json:"elligator2"`
}

func loadKATs(t *testing.T) cpaceKATs {
	t.Helper()
	data, err := os.ReadFile("testdata/cpace-kats.json")
	if err != nil {
		t.Fatalf("read KATs: %v", err)
	}
	var k cpaceKATs
	if err := json.Unmarshal(data, &k); err != nil {
		t.Fatalf("parse KATs: %v", err)
	}
	return k
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestX25519_RFC7748Vectors(t *testing.T) {
	// RFC 7748 §5.2.
	cases := []struct{ scalar, u, want string }{
		{
			"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
			"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
			"c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
		},
		{
			"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
			"e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
			"95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
		},
	}
	for i, tc := range cases {
		got, err := curve25519.X25519(mustHex(t, tc.scalar), mustHex(t, tc.u))
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if !bytes.Equal(got, mustHex(t, tc.want)) {
			t.Errorf("vector %d = %x, want %s", i, got, tc.want)
		}
	}
}

func TestElligator2_ReferenceVectors(t *testing.T) {
	kats := loadKATs(t)
	if len(kats.Elligator2) == 0 {
		t.Fatal("no elligator2 vectors")
	}
	for i, v := range kats.Elligator2 {
		// r is stored little-endian in the vectors.
		r := new(big.Int).SetBytes(reverse(mustHex(t, v.R)))
		got := elligator2(r)
		if !bytes.Equal(got, mustHex(t, v.X)) {
			t.Errorf("elligator2 vector %d = %x, want %s", i, got, v.X)
		}
	}
}

// TestCPace_ReferenceVectors is the interop-critical check: matching these
// vectors (generated from the aiosendspin `cpace` package and shared with the
// .NET SDK) makes this implementation wire-compatible with both peers.
func TestCPace_ReferenceVectors(t *testing.T) {
	kats := loadKATs(t)
	if len(kats.CPace) == 0 {
		t.Fatal("no cpace vectors")
	}
	for i, v := range kats.CPace {
		prs, ci, sid := mustHex(t, v.PRS), mustHex(t, v.CI), mustHex(t, v.SID)
		ada, adb := mustHex(t, v.ADA), mustHex(t, v.ADB)

		if got := cpaceGenerator(prs, ci, sid); !bytes.Equal(got, mustHex(t, v.Generator)) {
			t.Errorf("vector %d generator = %x, want %s", i, got, v.Generator)
		}

		a, err := startCPaceWithScalar(CPaceInitiator, prs, sid, ci, ada, mustHex(t, v.ScalarA))
		if err != nil {
			t.Fatalf("vector %d start A: %v", i, err)
		}
		b, err := startCPaceWithScalar(CPaceResponder, prs, sid, ci, adb, mustHex(t, v.ScalarB))
		if err != nil {
			t.Fatalf("vector %d start B: %v", i, err)
		}
		if !bytes.Equal(a.PublicShare(), mustHex(t, v.Ya)) {
			t.Errorf("vector %d Ya = %x, want %s", i, a.PublicShare(), v.Ya)
		}
		if !bytes.Equal(b.PublicShare(), mustHex(t, v.Yb)) {
			t.Errorf("vector %d Yb = %x, want %s", i, b.PublicShare(), v.Yb)
		}

		if err := a.Derive(b.PublicShare(), adb); err != nil {
			t.Fatalf("vector %d derive A: %v", i, err)
		}
		if err := b.Derive(a.PublicShare(), ada); err != nil {
			t.Fatalf("vector %d derive B: %v", i, err)
		}
		iskA, _ := a.ISK()
		iskB, _ := b.ISK()
		if !bytes.Equal(iskA, mustHex(t, v.ISK)) {
			t.Errorf("vector %d ISK(A) = %x, want %s", i, iskA, v.ISK)
		}
		if !bytes.Equal(iskB, mustHex(t, v.ISK)) {
			t.Errorf("vector %d ISK(B) mismatch", i)
		}
		ta, _ := a.Tag()
		tb, _ := b.Tag()
		if !bytes.Equal(ta, mustHex(t, v.Ta)) {
			t.Errorf("vector %d Ta = %x, want %s", i, ta, v.Ta)
		}
		if !bytes.Equal(tb, mustHex(t, v.Tb)) {
			t.Errorf("vector %d Tb = %x, want %s", i, tb, v.Tb)
		}
		if !a.Verify(tb) || !b.Verify(ta) {
			t.Errorf("vector %d cross-verification failed", i)
		}
	}
}

func TestCPace_WrongPINFailsConfirmation(t *testing.T) {
	sid := make([]byte, 16)
	a, err := StartCPace(CPaceInitiator, []byte("1234"), sid, nil, []byte("server"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := StartCPace(CPaceResponder, []byte("9999"), sid, nil, []byte("client"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Derive(b.PublicShare(), []byte("client")); err != nil {
		t.Fatal(err)
	}
	if err := b.Derive(a.PublicShare(), []byte("server")); err != nil {
		t.Fatal(err)
	}
	ta, _ := a.Tag()
	tb, _ := b.Tag()
	if a.Verify(tb) || b.Verify(ta) {
		t.Error("mismatched PINs produced verifying tags")
	}
}

func TestCPace_MatchingPINFullRun(t *testing.T) {
	sid := bytes.Repeat([]byte{0xAB}, 32)
	a, _ := StartCPace(CPaceInitiator, []byte("12345678"), sid, nil, []byte("server"))
	b, _ := StartCPace(CPaceResponder, []byte("12345678"), sid, nil, []byte("client"))
	if err := a.Derive(b.PublicShare(), []byte("client")); err != nil {
		t.Fatal(err)
	}
	if err := b.Derive(a.PublicShare(), []byte("server")); err != nil {
		t.Fatal(err)
	}
	iskA, _ := a.ISK()
	iskB, _ := b.ISK()
	if !bytes.Equal(iskA, iskB) {
		t.Error("ISKs differ for a matching PIN")
	}
	ta, _ := a.Tag()
	tb, _ := b.Tag()
	if !a.Verify(tb) || !b.Verify(ta) {
		t.Error("matching PIN failed mutual confirmation")
	}
}

func TestCPace_LowOrderPeerShareRejected(t *testing.T) {
	b, _ := StartCPace(CPaceResponder, []byte("1234"), make([]byte, 8), nil, nil)
	if err := b.Derive(make([]byte, 32), nil); err == nil {
		t.Error("all-zero (low-order) peer share accepted")
	}
}

func TestCPace_DeriveOnce(t *testing.T) {
	a, _ := StartCPace(CPaceInitiator, []byte("1234"), make([]byte, 8), nil, nil)
	b, _ := StartCPace(CPaceResponder, []byte("1234"), make([]byte, 8), nil, nil)
	if err := a.Derive(b.PublicShare(), nil); err != nil {
		t.Fatal(err)
	}
	if err := a.Derive(b.PublicShare(), nil); err == nil {
		t.Error("second Derive accepted")
	}
}
