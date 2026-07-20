// ABOUTME: Tests for player-audio chunk encoding — round-trip and short-body.
package playback

import (
	"bytes"
	"testing"
)

func TestEncodeParseAudioChunk_RoundTrip(t *testing.T) {
	audio := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	body := EncodeAudioChunk(1_234_567, audio)
	if len(body) != AudioChunkHeaderSize+len(audio) {
		t.Fatalf("body len = %d, want %d", len(body), AudioChunkHeaderSize+len(audio))
	}
	ts, got, err := ParseAudioChunk(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ts != 1_234_567 {
		t.Errorf("timestamp = %d, want 1234567", ts)
	}
	if !bytes.Equal(got, audio) {
		t.Errorf("payload = %v, want %v", got, audio)
	}
}

func TestEncodeAudioChunk_EmptyPayload(t *testing.T) {
	body := EncodeAudioChunk(42, nil)
	ts, got, err := ParseAudioChunk(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ts != 42 || len(got) != 0 {
		t.Errorf("ts=%d payload=%v, want 42 and empty", ts, got)
	}
}

func TestParseAudioChunk_ShortBody(t *testing.T) {
	if _, _, err := ParseAudioChunk([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("expected error for body shorter than header")
	}
}
