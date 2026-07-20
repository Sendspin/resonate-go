// ABOUTME: Package playback models spec-v2 player timing state and the
// ABOUTME: send-ahead scheduling computation the server uses to pace audio.

// Package playback holds the spec-v2 player-side timing model, the server's
// send-ahead scheduling math, and the playback Group that fans audio out to a
// synchronized set of players: how far ahead of playback the server schedules
// each player's audio, how a group's common send-ahead is derived, how a
// player's buffer_capacity byte cap bounds queued duration, and the
// player-audio binary chunk framing.
//
// The timing and send-ahead functions are pure logic over timing parameters
// and codec byte rates. Group ties them to the transport through a small
// ChunkWriter interface (satisfied by *secure.Conn), tracking each member's
// timing, availability, and buffered bytes and pacing chunk fan-out under each
// member's buffer_capacity. Spec reference:
// https://github.com/Sendspin/spec — "Player messages" / "Server behavior".
package playback
