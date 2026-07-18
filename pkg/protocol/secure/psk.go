// ABOUTME: Pre-shared-key machinery — psk_id derivation and the published
// ABOUTME: Sentinel PSK constant per the spec's Encryption section.
package secure

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// b64 is unpadded base64url, the encoding for every 32-byte value the spec
// puts on the wire (identities, psk_ids, PSKs, nonces).
var b64 = base64.RawURLEncoding

// Labels are the exact UTF-8 byte sequences from the spec — no NUL
// terminator, no separator. Changing them breaks interop with every other
// implementation.
const (
	pskIDLabel    = "sendspin-psk-id-v1"
	sentinelLabel = "sendspin-sentinel-psk-v1"
)

// PSK is a 32-byte pre-shared symmetric key mixed into the Noise handshake
// (psk2 placement). Long-term, Pairing, and Sentinel PSKs all share this
// representation; the stored category, not the value, determines how a match
// is handled.
type PSK [KeySize]byte

// NewPSK draws a fresh PSK from crypto/rand, for pairing flows that mint
// long-term keys.
func NewPSK() (PSK, error) {
	var p PSK
	if _, err := rand.Read(p[:]); err != nil {
		return PSK{}, fmt.Errorf("generate psk: %w", err)
	}
	return p, nil
}

// ID derives the psk_id the server sends in Noise message 1 so the client
// can select the right PSK: base64url(SHA-256("sendspin-psk-id-v1" || PSK)).
func (p PSK) ID() string {
	h := sha256.New()
	h.Write([]byte(pskIDLabel))
	h.Write(p[:])
	return b64.EncodeToString(h.Sum(nil))
}

// String returns the unpadded base64url encoding of the PSK itself (the
// wire form of client/pair-finalize's long_term_psk and management/
// add-record's psk fields).
func (p PSK) String() string {
	return b64.EncodeToString(p[:])
}

// ParsePSK decodes a 43-char unpadded base64url PSK.
func ParsePSK(s string) (PSK, error) {
	if len(s) != IDLength {
		return PSK{}, fmt.Errorf("psk must be %d characters, got %d", IDLength, len(s))
	}
	raw, err := b64.DecodeString(s)
	if err != nil {
		return PSK{}, fmt.Errorf("psk is not valid base64url: %w", err)
	}
	if len(raw) != KeySize {
		return PSK{}, fmt.Errorf("psk decodes to %d bytes, want %d", len(raw), KeySize)
	}
	var p PSK
	copy(p[:], raw)
	return p, nil
}

// SentinelPSK returns the published constant used as the PSK whenever no
// pairing record applies: SHA-256("sendspin-sentinel-psk-v1"). It provides
// no authentication on its own — its value is public by design.
func SentinelPSK() PSK {
	return PSK(sha256.Sum256([]byte(sentinelLabel)))
}
