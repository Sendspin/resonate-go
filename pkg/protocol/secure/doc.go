// ABOUTME: Package secure implements the cryptographic primitives of the
// ABOUTME: Sendspin spec's Encryption section: identities and PSK machinery.

// Package secure provides the building blocks for Sendspin's encrypted
// transport: Curve25519 identities (whose base64url public keys serve as
// client_id / server_id) and pre-shared-key handling, including psk_id
// derivation and the published Sentinel PSK.
//
// The Noise handshake state machine and transport framing build on this
// package. Spec reference: https://github.com/Sendspin/spec — "Encryption".
package secure
