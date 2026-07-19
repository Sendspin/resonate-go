// ABOUTME: The send-ahead scheduling computation — per-player lead, group
// ABOUTME: common send-ahead, and buffer_capacity-bounded queued duration.
package playback

// SourceKind distinguishes a live source (playback cannot buffer past the
// present, so the lead must be minimal) from a buffered source (the server
// may read ahead and grant more lead without adding latency).
type SourceKind int

const (
	// SourceLive is a real-time source (line-in, live radio): the buffer
	// cannot grow after playback begins.
	SourceLive SourceKind = iota
	// SourceBuffered is a seekable/file/queue source: the server can read
	// ahead and fill each player's queue.
	SourceBuffered
)

// PerPlayerSendAheadMs computes how far ahead of playback the server should
// schedule a single player's first chunk, per the spec's Server behavior:
//
//   - The baseline lead is min_buffer_ms.
//   - For a buffered source the lead may be extended toward
//     required_lead_time_ms (it adds no latency when the server can read
//     ahead); for a live source it is not (extending would add latency).
//   - static_delay_ms is then added on top — the server applies it separately
//     rather than folding it into the reported timing fields.
func PerPlayerSendAheadMs(t Timing, kind SourceKind) int {
	base := t.MinBufferMs
	if kind == SourceBuffered && t.RequiredLeadTimeMs > base {
		base = t.RequiredLeadTimeMs
	}
	return base + t.StaticDelayMs
}

// GroupSendAheadMs is the common send-ahead for a group: the maximum
// per-player send-ahead across its members, so every player has at least its
// required lead. Returns 0 for an empty group.
func GroupSendAheadMs(timings []Timing, kind SourceKind) int {
	max := 0
	for _, t := range timings {
		if sa := PerPlayerSendAheadMs(t, kind); sa > max {
			max = sa
		}
	}
	return max
}

// MaxQueuedDurationMs returns how many milliseconds of audio fit within a
// player's buffer_capacity at the given compressed byte rate (bytes per
// second for the negotiated codec). A non-positive byte rate or zero capacity
// yields 0. This is the hard cap: the server must not queue audio whose
// compressed size would exceed buffer_capacity.
func MaxQueuedDurationMs(bufferCapacityBytes, codecByteRatePerSec int) int {
	if bufferCapacityBytes <= 0 || codecByteRatePerSec <= 0 {
		return 0
	}
	return bufferCapacityBytes * 1000 / codecByteRatePerSec
}

// EffectiveQueuedMs is the queued duration the server can actually sustain
// for a player: the requested min_buffer_ms, capped by what buffer_capacity
// allows at the codec's byte rate. For live streams the spec requires queued
// duration to stay at or above min_buffer_ms, but buffer_capacity can force
// it lower when the codec's byte rate is high — this returns that effective
// value, and Underruns reports whether the cap bit.
func EffectiveQueuedMs(t Timing, codecByteRatePerSec int) int {
	capMs := MaxQueuedDurationMs(t.BufferCapacity, codecByteRatePerSec)
	if capMs < t.MinBufferMs {
		return capMs
	}
	return t.MinBufferMs
}

// BufferCapacityLimits reports whether a player's buffer_capacity forces its
// effective queued duration below the requested min_buffer_ms at the given
// codec byte rate.
func BufferCapacityLimits(t Timing, codecByteRatePerSec int) bool {
	return MaxQueuedDurationMs(t.BufferCapacity, codecByteRatePerSec) < t.MinBufferMs
}

// PCMByteRatePerSec returns the uncompressed PCM byte rate for a format:
// sample_rate × channels × bytes-per-sample. 24-bit packs into 3 bytes.
// Compressed codecs (opus/flac) have a variable rate the server measures
// from actual output; callers pass that measured rate to the functions above.
func PCMByteRatePerSec(sampleRate, channels, bitDepth int) int {
	return sampleRate * channels * (bitDepth / 8)
}
