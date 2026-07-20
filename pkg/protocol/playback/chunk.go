// ABOUTME: Player-audio binary message encoding — the type byte and the
// ABOUTME: 8-byte microsecond timestamp header that precedes each chunk payload.
package playback

import (
	"encoding/binary"
	"fmt"
)

// Player-audio binary message types. The spec encodes the role in bits 7–2 and
// the slot in bits 1–0; the player role owns types 4–7 (four slots). A group's
// primary audio stream is slot 0.
const (
	// PlayerAudioMsgType is the transport message type for a player-role audio
	// chunk on slot 0. Pass it as the msgType to Conn.WriteMessage.
	PlayerAudioMsgType byte = 4
)

// AudioChunkHeaderSize is the binary header carried inside a player-audio
// message body: an 8-byte big-endian microsecond playback timestamp. The
// 1-byte transport message type is not part of the body — the transport frame
// carries it separately (Conn.WriteMessage prepends it).
const AudioChunkHeaderSize = 8

// EncodeAudioChunk builds a player-audio message body: the 8-byte big-endian
// playback timestamp (server clock, microseconds) followed by the codec
// payload. Send it with Conn.WriteMessage(PlayerAudioMsgType, body).
func EncodeAudioChunk(timestampUS int64, audio []byte) []byte {
	body := make([]byte, AudioChunkHeaderSize+len(audio))
	binary.BigEndian.PutUint64(body[:AudioChunkHeaderSize], uint64(timestampUS))
	copy(body[AudioChunkHeaderSize:], audio)
	return body
}

// ParseAudioChunk splits a player-audio message body into its playback
// timestamp and codec payload. It errors if the body is shorter than the
// 8-byte header.
func ParseAudioChunk(body []byte) (timestampUS int64, audio []byte, err error) {
	if len(body) < AudioChunkHeaderSize {
		return 0, nil, fmt.Errorf("audio chunk body %d bytes, need at least %d", len(body), AudioChunkHeaderSize)
	}
	timestampUS = int64(binary.BigEndian.Uint64(body[:AudioChunkHeaderSize]))
	return timestampUS, body[AudioChunkHeaderSize:], nil
}
