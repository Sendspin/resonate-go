// ABOUTME: Package session implements the spec-v2 session model on top of the
// ABOUTME: encrypted transport: hellos, server/activate rules, goodbyes.

// Package session provides the typed core messages of the Sendspin spec's
// Communication section and the post-handshake session establishment flow:
// server/hello → client/hello → server/activate, including the
// activity-set admissibility rules tied to the matched PSK category.
//
// It builds on pkg/protocol/secure's Conn and carries no legacy (pre-v2)
// message shapes: the spec-v2 line is a hard cutover.
package session
