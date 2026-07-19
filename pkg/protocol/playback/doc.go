// ABOUTME: Package playback models spec-v2 player timing state and the
// ABOUTME: send-ahead scheduling computation the server uses to pace audio.

// Package playback holds the spec-v2 player-side timing model and the
// server's send-ahead scheduling math: how far ahead of playback the server
// schedules each player's audio, how a group's common send-ahead is derived,
// and how a player's buffer_capacity byte cap bounds queued duration.
//
// Everything here is pure logic over timing parameters and codec byte rates,
// independent of the transport. Spec reference:
// https://github.com/Sendspin/spec — "Player messages" / "Server behavior".
package playback
