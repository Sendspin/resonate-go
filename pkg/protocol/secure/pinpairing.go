// ABOUTME: Deterministic PIN-pairing primitives — PAKE sid, dynamic-PIN
// ABOUTME: commit/derive, and PSK wrapping under the CPace output.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
)

// CPace associated data for the two roles.
var (
	CPaceADServer = []byte("server")
	CPaceADClient = []byte("client")
)

// Spec labels (exact UTF-8 bytes, no NUL, no separator).
var (
	pakeSIDLabel = []byte("sendspin-pair-pake-v1")
	commitLabel  = []byte("sendspin-pair-commit-v1")
	pinLabel     = []byte("sendspin-pin-derive-v1")
	pskWrapLabel = []byte("sendspin-pair-psk-wrap-v1")
)

// wrapNonce is the 12-byte all-zero nonce used for PSK wrapping (the key is
// single-use, so a fixed nonce is safe).
var wrapNonce = make([]byte, 12)

// BuildPakeSID constructs the CPace session id:
// "sendspin-pair-pake-v1" || h || counter, where h is the Noise handshake
// hash and counter is the number of pairing server/activate messages since
// the last handshake (big-endian uint32).
func BuildPakeSID(handshakeHash []byte, pairingCounter uint32) []byte {
	sid := make([]byte, 0, len(pakeSIDLabel)+len(handshakeHash)+4)
	sid = append(sid, pakeSIDLabel...)
	sid = append(sid, handshakeHash...)
	sid = binary.BigEndian.AppendUint32(sid, pairingCounter)
	return sid
}

// CommitB computes the dynamic-PIN commitment:
// SHA-256("sendspin-pair-commit-v1" || nonce_B).
func CommitB(nonceB []byte) []byte {
	sum := sha256.Sum256(concat(commitLabel, nonceB))
	return sum[:]
}

// DerivePIN derives the dynamic PIN from the handshake hash and nonces:
// SHA-256("sendspin-pin-derive-v1" || h || nonce_A || nonce_B) interpreted as
// an unsigned big-endian integer mod 10^length, zero-padded to length digits.
func DerivePIN(handshakeHash, nonceA, nonceB []byte, length int) string {
	sum := sha256.Sum256(concat(pinLabel, handshakeHash, nonceA, nonceB))
	digest := new(big.Int).SetBytes(sum[:]) // big-endian
	modulus := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	pin := new(big.Int).Mod(digest, modulus)
	return fmt.Sprintf("%0*s", length, pin.String())
}

// ClampPINLength computes the negotiated PIN length: max(clientMin, serverMin)
// clamped to [4, 12].
func ClampPINLength(clientMin, serverMin int) int {
	l := clientMin
	if serverMin > l {
		l = serverMin
	}
	if l < 4 {
		l = 4
	}
	if l > 12 {
		l = 12
	}
	return l
}

// wrapAEAD builds the AEAD for PSK wrapping under the given suite and key.
func wrapAEAD(suite Suite, key []byte) (cipher.AEAD, error) {
	switch suite {
	case SuiteAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case SuiteChaChaPoly:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("unknown suite %q for psk wrapping", string(suite))
	}
}

// wrapKey derives K_wrap = SHA-256("sendspin-pair-psk-wrap-v1" || sid || ISK).
func wrapKey(sid, isk []byte) []byte {
	sum := sha256.Sum256(concat(pskWrapLabel, sid, isk))
	return sum[:]
}

// WrapPSK seals psk under K_wrap with the session suite's AEAD, a 12-byte
// zero nonce, and empty associated data. Returns the 48-byte
// ciphertext-plus-tag.
func WrapPSK(sid, isk []byte, psk PSK, suite Suite) ([]byte, error) {
	aead, err := wrapAEAD(suite, wrapKey(sid, isk))
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, wrapNonce, psk[:], nil), nil
}

// UnwrapPSK opens a wrapped PSK produced by WrapPSK.
func UnwrapPSK(sid, isk, wrapped []byte, suite Suite) (PSK, error) {
	aead, err := wrapAEAD(suite, wrapKey(sid, isk))
	if err != nil {
		return PSK{}, err
	}
	plain, err := aead.Open(nil, wrapNonce, wrapped, nil)
	if err != nil {
		return PSK{}, fmt.Errorf("unwrap psk: %w", err)
	}
	if len(plain) != KeySize {
		return PSK{}, fmt.Errorf("unwrapped psk is %d bytes, want %d", len(plain), KeySize)
	}
	var p PSK
	copy(p[:], plain)
	return p, nil
}
