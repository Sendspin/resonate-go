// ABOUTME: Tests for the deterministic PIN-pairing primitives, anchored to
// ABOUTME: oracle values and cross-checked against PSK wrap/unwrap round trips.
package secure

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Oracle values independently computed from the spec constructions (SHA-256
// of the labelled concatenations). A drift here means incompatibility with
// every conformant peer.
func TestPINPrimitives_OracleValues(t *testing.T) {
	h := make([]byte, 32)
	for i := range h {
		h[i] = byte(i) // 00..1f
	}
	nonceA := bytes.Repeat([]byte{0xAA}, 32)
	nonceB := bytes.Repeat([]byte{0xBB}, 32)

	if got := hex.EncodeToString(CommitB(nonceB)); got != "c31ebe8c0282c9f764f4d67046eabdec64fccc2015bb9d2041ccf6501f35962e" {
		t.Errorf("CommitB = %s", got)
	}
	if got := DerivePIN(h, nonceA, nonceB, 6); got != "899599" {
		t.Errorf("DerivePIN(L=6) = %s, want 899599", got)
	}
	if got := DerivePIN(h, nonceA, nonceB, 8); got != "40899599" {
		t.Errorf("DerivePIN(L=8) = %s, want 40899599", got)
	}
	wantSID := "73656e647370696e2d706169722d70616b652d7631000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000003"
	if got := hex.EncodeToString(BuildPakeSID(h, 3)); got != wantSID {
		t.Errorf("BuildPakeSID = %s", got)
	}
}

func TestDerivePIN_LengthAndPadding(t *testing.T) {
	h := bytes.Repeat([]byte{0x01}, 32)
	nA := bytes.Repeat([]byte{0x02}, 32)
	nB := bytes.Repeat([]byte{0x03}, 32)
	for _, L := range []int{4, 6, 8, 12} {
		pin := DerivePIN(h, nA, nB, L)
		if len(pin) != L {
			t.Errorf("DerivePIN(L=%d) length = %d", L, len(pin))
		}
		for _, c := range pin {
			if c < '0' || c > '9' {
				t.Errorf("DerivePIN(L=%d) has non-digit: %q", L, pin)
			}
		}
	}
}

func TestClampPINLength(t *testing.T) {
	cases := []struct{ client, server, want int }{
		{6, 4, 6},
		{4, 8, 8},
		{2, 3, 4},   // below floor
		{20, 6, 12}, // above ceiling
		{12, 12, 12},
	}
	for _, tc := range cases {
		if got := ClampPINLength(tc.client, tc.server); got != tc.want {
			t.Errorf("ClampPINLength(%d,%d) = %d, want %d", tc.client, tc.server, got, tc.want)
		}
	}
}

func TestWrapPSK_RoundTripBothSuites(t *testing.T) {
	sid := BuildPakeSID(bytes.Repeat([]byte{0x11}, 32), 1)
	isk := bytes.Repeat([]byte{0xCC}, 64)
	psk, _ := NewPSK()

	for _, suite := range []Suite{SuiteChaChaPoly, SuiteAESGCM} {
		t.Run(string(suite), func(t *testing.T) {
			wrapped, err := WrapPSK(sid, isk, psk, suite)
			if err != nil {
				t.Fatal(err)
			}
			if len(wrapped) != KeySize+16 {
				t.Errorf("wrapped PSK is %d bytes, want %d", len(wrapped), KeySize+16)
			}
			back, err := UnwrapPSK(sid, isk, wrapped, suite)
			if err != nil {
				t.Fatalf("unwrap: %v", err)
			}
			if back != psk {
				t.Error("wrap/unwrap round trip mismatch")
			}
		})
	}
}

func TestWrapPSK_WrongKeyFails(t *testing.T) {
	sid := BuildPakeSID(bytes.Repeat([]byte{0x11}, 32), 1)
	isk := bytes.Repeat([]byte{0xCC}, 64)
	psk, _ := NewPSK()

	wrapped, err := WrapPSK(sid, isk, psk, SuiteChaChaPoly)
	if err != nil {
		t.Fatal(err)
	}
	// Different ISK derives a different K_wrap → AEAD open must fail.
	if _, err := UnwrapPSK(sid, bytes.Repeat([]byte{0xDD}, 64), wrapped, SuiteChaChaPoly); err == nil {
		t.Error("unwrap with wrong ISK succeeded")
	}
	// Tampered ciphertext must fail.
	wrapped[0] ^= 0x01
	if _, err := UnwrapPSK(sid, isk, wrapped, SuiteChaChaPoly); err == nil {
		t.Error("unwrap of tampered ciphertext succeeded")
	}
}

// The wrapped PSK produced under one suite must be transportable: the wrap
// key is suite-independent (SHA-256), only the AEAD differs, so a value
// wrapped with ChaChaPoly cannot be opened as AES-GCM.
func TestWrapPSK_SuiteMismatchFails(t *testing.T) {
	sid := BuildPakeSID(bytes.Repeat([]byte{0x11}, 32), 1)
	isk := bytes.Repeat([]byte{0xCC}, 64)
	psk, _ := NewPSK()

	wrapped, _ := WrapPSK(sid, isk, psk, SuiteChaChaPoly)
	if _, err := UnwrapPSK(sid, isk, wrapped, SuiteAESGCM); err == nil {
		t.Error("cross-suite unwrap succeeded")
	}
}
