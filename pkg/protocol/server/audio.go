// ABOUTME: The audio pump — reads a PCM Source, packs 20 ms chunks, timestamps
// ABOUTME: them send-ahead of playback, and broadcasts them into a group.
package server

import (
	"context"
	"fmt"
	"time"

	"github.com/Sendspin/sendspin-go/pkg/audio"
	"github.com/Sendspin/sendspin-go/pkg/protocol/playback"
	"github.com/Sendspin/sendspin-go/pkg/protocol/session"
)

// ChunkDurationMs is the fixed audio chunk length: 20 ms, 50 chunks per second,
// the interop-critical granularity every Sendspin implementation shares.
const ChunkDurationMs = 20

// ChunkDurationUS is ChunkDurationMs in microseconds.
const ChunkDurationUS = ChunkDurationMs * 1000

// Source is a PCM audio source the pump streams into a group. Read fills dst
// with interleaved int32 samples (24-bit-range values) and returns the count;
// a return of (0, io.EOF) — or any error — ends the stream.
type Source interface {
	// Format reports the source's PCM format.
	Format() audio.Format
	// Read fills dst with the next interleaved samples, returning the count.
	Read(dst []int32) (int, error)
}

// StreamOptions tunes StreamGroup.
type StreamOptions struct {
	// Tick is the pump period; 0 uses the 20 ms chunk duration. Tests shorten
	// it to run fast — playback timestamps come from the server clock, not the
	// tick, so a faster tick does not distort them.
	Tick time.Duration
}

// StreamGroup drives audio from src into the group until the source is
// exhausted or ctx is cancelled. It opens the stream (stream/start with the
// source's PCM format), then on each tick fills the group's send-ahead window
// with timestamped 20 ms chunks, and closes the stream (stream/end) on the way
// out. Each chunk's timestamp is its playback time on the server clock; chunks
// go out roughly send-ahead milliseconds before then.
func (s *Server) StreamGroup(ctx context.Context, groupID string, src Source, opts StreamOptions) error {
	f := src.Format()
	if f.SampleRate <= 0 || f.Channels <= 0 {
		return fmt.Errorf("source format invalid: %+v", f)
	}
	if f.BitDepth != 16 && f.BitDepth != 24 {
		return fmt.Errorf("unsupported bit depth %d (want 16 or 24)", f.BitDepth)
	}
	if err := s.groups.StartGroup(groupID, session.StreamStartPlayer{
		Codec: "pcm", Channels: f.Channels, SampleRate: f.SampleRate, BitDepth: f.BitDepth,
	}); err != nil {
		return err
	}
	defer func() { _ = s.groups.StopGroup(groupID) }()

	tick := opts.Tick
	if tick <= 0 {
		tick = ChunkDurationMs * time.Millisecond
	}
	frame := make([]int32, f.SampleRate*ChunkDurationMs/1000*f.Channels)

	// The next chunk's playback timestamp, seeded a send-ahead window ahead of
	// now so the first chunk has its full lead.
	nextTS := s.clock() + int64(s.groups.GroupByID(groupID).SendAheadMs())*1000

	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			now := s.clock()
			horizon := now + int64(s.groups.GroupByID(groupID).SendAheadMs())*1000
			for nextTS <= horizon {
				more, err := s.pumpChunk(groupID, src, frame, f.BitDepth, now, nextTS)
				if err != nil {
					return err
				}
				if !more {
					return nil // source exhausted — deferred StopGroup ends the stream
				}
				nextTS += ChunkDurationUS
			}
		}
	}
}

// pumpChunk reads one frame from src, PCM-encodes it at bitDepth, and
// broadcasts it to the group at playback time playbackTS as of nowUS. It
// reports whether the source produced a full frame; false means end of stream.
func (s *Server) pumpChunk(groupID string, src Source, frame []int32, bitDepth int, nowUS, playbackTS int64) (bool, error) {
	n, err := src.Read(frame)
	if err != nil && n == 0 {
		return false, nil // EOF or a source that is simply done
	}
	if n < len(frame) {
		// A short read ends the stream; a partial final frame is dropped rather
		// than sent under-length (players expect whole 20 ms chunks).
		return false, nil
	}
	payload := encodePCM(frame, bitDepth)
	g := s.groups.GroupByID(groupID)
	if g == nil {
		return false, fmt.Errorf("group %q gone mid-stream", groupID)
	}
	for _, r := range g.Broadcast(nowUS, playbackTS, ChunkDurationUS, func(*playback.Member) []byte { return payload }) {
		if r.Err != nil {
			// A broken member connection is that client's problem; the loop and
			// the rest of the group carry on. Its Handle loop will clean it up.
			continue
		}
	}
	return true, nil
}

// encodePCM packs interleaved int32 samples as little-endian PCM at the given
// bit depth: 24-bit as three bytes, 16-bit as two (the sample's top 16 bits).
func encodePCM(samples []int32, bitDepth int) []byte {
	if bitDepth == 16 {
		out := make([]byte, len(samples)*2)
		for i, s := range samples {
			v := audio.SampleToInt16(s)
			out[i*2] = byte(v)
			out[i*2+1] = byte(v >> 8)
		}
		return out
	}
	out := make([]byte, len(samples)*3)
	for i, s := range samples {
		b := audio.SampleTo24Bit(s)
		out[i*3], out[i*3+1], out[i*3+2] = b[0], b[1], b[2]
	}
	return out
}
