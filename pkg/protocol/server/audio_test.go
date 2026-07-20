// ABOUTME: Tests for the audio pump — PCM packing and an end-to-end stream of
// ABOUTME: timestamped chunks into an established player's group.
package server

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/Sendspin/sendspin-go/pkg/audio"
	"github.com/Sendspin/sendspin-go/pkg/protocol/playback"
	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
	"github.com/Sendspin/sendspin-go/pkg/protocol/session"
)

// sliceSource yields a fixed number of full frames whose constant sample value
// increases per frame (so chunks are distinguishable), then reports EOF.
type sliceSource struct {
	format audio.Format
	frames int
	sent   int
	value  int32
}

func (s *sliceSource) Format() audio.Format { return s.format }

func (s *sliceSource) Read(dst []int32) (int, error) {
	if s.sent >= s.frames {
		return 0, io.EOF
	}
	v := s.value + int32(s.sent) // distinct value per frame
	for i := range dst {
		dst[i] = v
	}
	s.sent++
	return len(dst), nil
}

func TestEncodePCM_24Bit(t *testing.T) {
	got := encodePCM([]int32{0x010203, -1}, 24)
	// 0x010203 → 03 02 01 ; -1 → FF FF FF (two's complement low 24 bits).
	want := []byte{0x03, 0x02, 0x01, 0xff, 0xff, 0xff}
	if string(got) != string(want) {
		t.Errorf("24-bit = % x, want % x", got, want)
	}
}

func TestEncodePCM_16Bit(t *testing.T) {
	// SampleToInt16 shifts right 8: 0x010203 → 0x0102.
	got := encodePCM([]int32{0x010203}, 16)
	want := []byte{0x02, 0x01} // little-endian 0x0102
	if string(got) != string(want) {
		t.Errorf("16-bit = % x, want % x", got, want)
	}
}

func TestStreamGroup_RejectsBadFormat(t *testing.T) {
	s, _, _ := harness(t, nil)
	err := s.StreamGroup(context.Background(), "nope", &sliceSource{
		format: audio.Format{SampleRate: 48000, Channels: 2, BitDepth: 12},
	}, StreamOptions{})
	if err == nil {
		t.Fatal("expected error for unsupported bit depth")
	}
}

func TestStreamGroup_EndToEnd(t *testing.T) {
	s, srv, _ := harness(t, nil)
	clientID, _ := secure.GenerateIdentity()
	conn := dialAndEstablish(t, srv, clientID)
	defer conn.Close()
	readControl(t, conn) // initial solo group/update

	// Make the player available with a 100 ms buffer so the whole short stream
	// fits inside a single send-ahead window (all chunks burst on tick one).
	avail := true
	minBuf := 100
	sendControl(t, conn, session.ClientState{Available: &avail, Player: &session.ClientPlayerState{MinBufferMs: &minBuf}})
	sendControl(t, conn, session.ClientTime{ClientTransmitted: 1})
	if st := readControl(t, conn).(*session.ServerTime); st.ClientTransmitted != 1 {
		t.Fatal("barrier failed")
	}

	groupID := s.Groups().GroupID(clientID.ID())
	const nFrames = 3
	format := audio.Format{SampleRate: 48000, Channels: 2, BitDepth: 24}
	src := &sliceSource{format: format, frames: nFrames, value: 1000}

	streamErr := make(chan error, 1)
	go func() {
		streamErr <- s.StreamGroup(context.Background(), groupID, src, StreamOptions{Tick: 2 * time.Millisecond})
	}()

	// Stream open: group/update(playing) then stream/start(pcm).
	if gu, ok := readControl(t, conn).(*session.GroupUpdate); !ok || gu.PlaybackState != session.PlaybackPlaying {
		t.Fatalf("expected group/update playing, got %#v", gu)
	}
	ss, ok := readControl(t, conn).(*session.StreamStart)
	if !ok || ss.Player == nil || ss.Player.Codec != "pcm" || ss.Player.BitDepth != 24 {
		t.Fatalf("expected pcm stream/start, got %#v", ss)
	}

	// N audio chunks, timestamps exactly one chunk apart, payload decoding to
	// the source's per-frame constant.
	frameLen := format.SampleRate * ChunkDurationMs / 1000 * format.Channels
	var prevTS int64
	for i := 0; i < nFrames; i++ {
		mt, body, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read chunk %d: %v", i, err)
		}
		if mt != playback.PlayerAudioMsgType {
			t.Fatalf("chunk %d msg type = %d, want %d", i, mt, playback.PlayerAudioMsgType)
		}
		ts, pcm, err := playback.ParseAudioChunk(body)
		if err != nil {
			t.Fatalf("chunk %d parse: %v", i, err)
		}
		if len(pcm) != frameLen*3 {
			t.Errorf("chunk %d pcm len = %d, want %d", i, len(pcm), frameLen*3)
		}
		if i > 0 && ts-prevTS != ChunkDurationUS {
			t.Errorf("chunk %d ts delta = %d, want %d", i, ts-prevTS, ChunkDurationUS)
		}
		prevTS = ts
		// First sample decodes to the frame's constant (1000 + i).
		want := int32(1000 + i)
		got := int32(pcm[0]) | int32(pcm[1])<<8 | int32(pcm[2])<<16
		if got != want {
			t.Errorf("chunk %d first sample = %d, want %d", i, got, want)
		}
	}

	// Source exhausted → StreamGroup returns nil and the stream closes:
	// stream/end then group/update(stopped).
	if err := <-streamErr; err != nil {
		t.Fatalf("StreamGroup returned %v", err)
	}
	if _, ok := readControl(t, conn).(*session.StreamEnd); !ok {
		t.Fatal("expected stream/end after source exhausted")
	}
	if gu, ok := readControl(t, conn).(*session.GroupUpdate); !ok || gu.PlaybackState != session.PlaybackStopped {
		t.Fatalf("expected group/update stopped, got %#v", gu)
	}
}
