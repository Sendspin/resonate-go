// ABOUTME: Noise cipher suites defined by the Sendspin spec and their
// ABOUTME: mapping onto flynn/noise cipher suite implementations.
package secure

import (
	"fmt"

	"github.com/flynn/noise"
)

// Suite names the <DH>_<cipher>_<hash> part of the full Noise protocol name.
// The client picks one in client/init; servers must support both, so no
// negotiation happens on the wire.
type Suite string

const (
	// SuiteChaChaPoly is the software-friendly suite.
	SuiteChaChaPoly Suite = "25519_ChaChaPoly_SHA256"
	// SuiteAESGCM is the hardware-accelerated suite (AES-NI / ARMv8 CE).
	SuiteAESGCM Suite = "25519_AESGCM_SHA256"
)

// cipherSuite maps the wire name onto a flynn/noise cipher suite.
func (s Suite) cipherSuite() (noise.CipherSuite, error) {
	switch s {
	case SuiteChaChaPoly:
		return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), nil
	case SuiteAESGCM:
		return noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256), nil
	default:
		return nil, fmt.Errorf("unknown cipher suite %q", string(s))
	}
}

// Valid reports whether s is one of the spec-defined suites.
func (s Suite) Valid() bool {
	_, err := s.cipherSuite()
	return err == nil
}
