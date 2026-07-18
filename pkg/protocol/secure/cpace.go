// ABOUTME: CPACE-X25519-SHA512 with mutual confirmation — the PAKE backing
// ABOUTME: Sendspin's PIN pairing flows (draft-irtf-cfrg-cpace).
package secure

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"math/big"

	"golang.org/x/crypto/curve25519"
)

// CPaceRole is the initiator/responder role. Sendspin maps the server to the
// initiator (A) and the client to the responder (B).
type CPaceRole int

const (
	// CPaceInitiator is role A (the Sendspin server).
	CPaceInitiator CPaceRole = iota
	// CPaceResponder is role B (the Sendspin client).
	CPaceResponder
)

// CPace domain-separation labels from the draft's X25519-SHA512 instance.
var (
	cpaceDSI      = []byte("CPace255")
	cpaceDSIISK   = []byte("CPace255_ISK")
	cpaceMacLabel = []byte("CPaceMac")
)

const (
	cpaceFieldBytes = 32
	sha512BlockLen  = 128
)

// fieldPrime is 2^255 - 19.
var fieldPrime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// CPace is one side of a CPACE-X25519-SHA512 run with explicit mutual
// confirmation. Single-use; not constant-time in its field arithmetic, which
// is acceptable for the one-shot interactive PIN flows where every secret is
// a per-session ephemeral. Construction is verified against the aiosendspin
// reference implementation's known-answer vectors.
type CPace struct {
	role       CPaceRole
	sid        []byte
	ad         []byte
	scalar     []byte
	pubShare   []byte
	derived    bool
	isk        []byte
	macKey     []byte
	sideAShare []byte
	sideAAD    []byte
	sideBShare []byte
	sideBAD    []byte
}

// StartCPace begins a CPace run: samples a scalar and computes this side's
// public share from the PRS-derived generator. prs is the password (the PIN
// ASCII digits for Sendspin), sid the session id, ci the channel identifier
// (empty for Sendspin), ad this side's associated data ("server"/"client").
func StartCPace(role CPaceRole, prs, sid, ci, ad []byte) (*CPace, error) {
	scalar := make([]byte, cpaceFieldBytes)
	if _, err := rand.Read(scalar); err != nil {
		return nil, fmt.Errorf("sample cpace scalar: %w", err)
	}
	return startCPaceWithScalar(role, prs, sid, ci, ad, scalar)
}

// startCPaceWithScalar is the deterministic variant used by known-answer tests.
func startCPaceWithScalar(role CPaceRole, prs, sid, ci, ad, scalar []byte) (*CPace, error) {
	gen := cpaceGenerator(prs, ci, sid)
	share, err := curve25519.X25519(scalar, gen)
	if err != nil {
		return nil, fmt.Errorf("generator encodes a low-order point: %w", err)
	}
	return &CPace{
		role:     role,
		sid:      append([]byte(nil), sid...),
		ad:       append([]byte(nil), ad...),
		scalar:   scalar,
		pubShare: share,
	}, nil
}

// PublicShare returns this side's public share (Ya for A, Yb for B).
func (c *CPace) PublicShare() []byte { return append([]byte(nil), c.pubShare...) }

// Derive ingests the peer's share, computing the ISK and the confirmation
// MAC key. It may be called at most once.
func (c *CPace) Derive(peerShare, peerAD []byte) error {
	if c.scalar == nil {
		return fmt.Errorf("cpace: Derive may only be called once")
	}
	scalar := c.scalar
	c.scalar = nil
	if len(peerShare) != cpaceFieldBytes {
		return fmt.Errorf("cpace: peer share must be %d bytes", cpaceFieldBytes)
	}
	shared, err := curve25519.X25519(scalar, peerShare)
	if err != nil {
		return fmt.Errorf("cpace: peer share encodes a low-order point: %w", err)
	}

	if c.role == CPaceInitiator {
		c.sideAShare, c.sideAAD = c.pubShare, c.ad
		c.sideBShare, c.sideBAD = append([]byte(nil), peerShare...), append([]byte(nil), peerAD...)
	} else {
		c.sideAShare, c.sideAAD = append([]byte(nil), peerShare...), append([]byte(nil), peerAD...)
		c.sideBShare, c.sideBAD = c.pubShare, c.ad
	}

	var iskInput []byte
	iskInput = append(iskInput, lvCat(cpaceDSIISK, c.sid, shared)...)
	iskInput = append(iskInput, lvCat(c.sideAShare, c.sideAAD)...)
	iskInput = append(iskInput, lvCat(c.sideBShare, c.sideBAD)...)
	isk := sha512.Sum512(iskInput)
	c.isk = isk[:]

	macKey := sha512.Sum512(concat(cpaceMacLabel, c.sid, c.isk))
	c.macKey = macKey[:]
	c.derived = true
	return nil
}

// ISK returns the 64-byte intermediate session key. Derive must run first.
func (c *CPace) ISK() ([]byte, error) {
	if !c.derived {
		return nil, fmt.Errorf("cpace: Derive must be called first")
	}
	return append([]byte(nil), c.isk...), nil
}

// Tag returns this side's 64-byte confirmation tag (Ta for A, Tb for B).
func (c *CPace) Tag() ([]byte, error) { return c.mac(true) }

// Verify reports whether the peer's tag proves knowledge of the PRS.
func (c *CPace) Verify(peerTag []byte) bool {
	if !c.derived {
		return false
	}
	// Reflection guard: identical shares+AD would make the peer's expected
	// tag equal our own.
	if subtle.ConstantTimeCompare(c.sideAShare, c.sideBShare) == 1 &&
		subtle.ConstantTimeCompare(c.sideAAD, c.sideBAD) == 1 {
		return false
	}
	want, err := c.mac(false)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(peerTag, want) == 1
}

func (c *CPace) mac(own bool) ([]byte, error) {
	if !c.derived {
		return nil, fmt.Errorf("cpace: Derive must be called first")
	}
	var share, ad []byte
	if own == (c.role == CPaceInitiator) {
		share, ad = c.sideAShare, c.sideAAD
	} else {
		share, ad = c.sideBShare, c.sideBAD
	}
	h := hmac.New(sha512.New, c.macKey)
	h.Write(lvCat(share, ad))
	return h.Sum(nil), nil
}

// cpaceGenerator derives the CPace generator point from the password.
func cpaceGenerator(prs, ci, sid []byte) []byte {
	zpad := sha512BlockLen - 1 - len(prependLen(prs)) - len(prependLen(cpaceDSI))
	if zpad < 0 {
		zpad = 0
	}
	genString := lvCat(cpaceDSI, prs, make([]byte, zpad), ci, sid)
	h := sha512.Sum512(genString)
	return elligator2(decodeU(h[:cpaceFieldBytes]))
}

// elligator2 maps a field element to a Curve25519 u-coordinate, per the
// draft's map used to build the CPace generator.
func elligator2(r *big.Int) []byte {
	p := fieldPrime
	a := big.NewInt(486662)
	z := big.NewInt(2)
	inv2 := new(big.Int).ModInverse(big.NewInt(2), p)

	r = mod(r)
	// denom = 1 + Z*r^2
	denom := mod(new(big.Int).Add(big.NewInt(1), mul(z, mul(r, r))))
	// v = -A * inv0(denom)
	v := mod(new(big.Int).Neg(mul(a, inv0(denom))))
	// eps = legendre(v^3 + A*v^2 + v)
	vv := mul(v, v)
	inner := mod(new(big.Int).Add(new(big.Int).Add(mul(vv, v), mul(a, vv)), v))
	eps := new(big.Int).Exp(inner, new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1), p)
	// x = eps*v - (1-eps)*A*inv2
	oneMinusEps := new(big.Int).Sub(big.NewInt(1), eps)
	x := mod(new(big.Int).Sub(mul(eps, v), mul(mul(oneMinusEps, a), inv2)))
	return encodeU(x)
}

// --- helpers ---

// prependLen encodes a length as little-endian base-128 with continuation
// bits, then prefixes the data (the draft's LV encoding).
func prependLen(data []byte) []byte {
	length := len(data)
	var prefix []byte
	for {
		prefix = append(prefix, byte(length&0x7F))
		length >>= 7
		if length == 0 {
			break
		}
		prefix[len(prefix)-1] |= 0x80
	}
	return append(prefix, data...)
}

// lvCat length-prefixes each part and concatenates them.
func lvCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, prependLen(p)...)
	}
	return out
}

// concat joins byte slices with no length prefixing.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// decodeU reads a little-endian field element, masking the unused top bit.
func decodeU(u []byte) *big.Int {
	b := make([]byte, cpaceFieldBytes)
	copy(b, u)
	b[31] &= 0x7F
	return new(big.Int).SetBytes(reverse(b))
}

// encodeU writes a field element little-endian into 32 bytes.
func encodeU(x *big.Int) []byte {
	be := x.Bytes()
	le := reverse(be)
	out := make([]byte, cpaceFieldBytes)
	copy(out, le)
	return out
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func mod(x *big.Int) *big.Int {
	r := new(big.Int).Mod(x, fieldPrime)
	if r.Sign() < 0 {
		r.Add(r, fieldPrime)
	}
	return r
}

func mul(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }

// inv0 is modular inverse with inv0(0) = 0.
func inv0(x *big.Int) *big.Int {
	if x.Sign() == 0 {
		return big.NewInt(0)
	}
	return new(big.Int).Exp(x, new(big.Int).Sub(fieldPrime, big.NewInt(2)), fieldPrime)
}
