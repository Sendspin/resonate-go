// ABOUTME: Sendspin identity — Curve25519 static keypair whose base64url
// ABOUTME: public key is the client_id / server_id on the wire.
package secure

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	// KeySize is the size in bytes of Curve25519 keys and of Sendspin PSKs.
	KeySize = 32

	// IDLength is the length of an encoded identity or psk_id: 32 bytes in
	// unpadded base64url is exactly 43 characters.
	IDLength = 43
)

// Identity is a Curve25519 static keypair. The base64url-encoded public key
// is the Sendspin client_id / server_id; the keypair doubles as the Noise
// static key. Rotating the keypair changes the identity, so servers must
// persist it (see LoadOrGenerate) and treat it as part of their backup set.
type Identity struct {
	private [KeySize]byte
	public  [KeySize]byte
}

// GenerateIdentity creates a new random identity.
func GenerateIdentity() (*Identity, error) {
	var priv [KeySize]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	return identityFromPrivate(priv)
}

func identityFromPrivate(priv [KeySize]byte) (*Identity, error) {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	id := &Identity{private: priv}
	copy(id.public[:], pub)
	return id, nil
}

// ID returns the wire identity: the unpadded base64url encoding of the
// public key, always exactly IDLength characters.
func (id *Identity) ID() string {
	return b64.EncodeToString(id.public[:])
}

// PublicKey returns a copy of the raw 32-byte public key.
func (id *Identity) PublicKey() []byte {
	out := make([]byte, KeySize)
	copy(out, id.public[:])
	return out
}

// PrivateKey returns a copy of the raw 32-byte private key, for handing to
// the Noise handshake. Callers must not persist or log it.
func (id *Identity) PrivateKey() []byte {
	out := make([]byte, KeySize)
	copy(out, id.private[:])
	return out
}

// ParseID decodes a wire identity (43-char unpadded base64url) into the raw
// 32-byte public key.
func ParseID(s string) ([]byte, error) {
	if len(s) != IDLength {
		return nil, fmt.Errorf("identity must be %d characters, got %d", IDLength, len(s))
	}
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("identity is not valid base64url: %w", err)
	}
	if len(raw) != KeySize {
		return nil, fmt.Errorf("identity decodes to %d bytes, want %d", len(raw), KeySize)
	}
	return raw, nil
}

// LoadOrGenerateIdentity loads the identity persisted at path, or generates
// a new one and persists it (file mode 0600, parent directories 0700) if the
// file does not exist. The file holds the base64url private key on a single
// line.
func LoadOrGenerateIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parseIdentityFile(path, data)
	case os.IsNotExist(err):
		return generateAndPersist(path)
	default:
		return nil, fmt.Errorf("read identity %s: %w", path, err)
	}
}

func parseIdentityFile(path string, data []byte) (*Identity, error) {
	enc := strings.TrimSpace(string(data))
	raw, err := b64.DecodeString(enc)
	if err != nil || len(raw) != KeySize {
		return nil, fmt.Errorf("identity file %s is corrupt (want %d base64url bytes)", path, KeySize)
	}
	var priv [KeySize]byte
	copy(priv[:], raw)
	return identityFromPrivate(priv)
}

func generateAndPersist(path string) (*Identity, error) {
	id, err := GenerateIdentity()
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create identity dir: %w", err)
		}
	}
	line := b64.EncodeToString(id.private[:]) + "\n"
	// 0600: the private key IS the server's identity; world-readable would
	// let any local user impersonate it.
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		return nil, fmt.Errorf("persist identity %s: %w", path, err)
	}
	return id, nil
}
