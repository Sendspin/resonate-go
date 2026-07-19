// ABOUTME: Player timing state and client/state delta-merge semantics.
package playback

import "fmt"

// Spec bounds for static_delay_ms.
const (
	MinStaticDelayMs = 0
	MaxStaticDelayMs = 5000
)

// Timing is a player's server-tracked timing state, populated from the
// player object of client/state. All three fields are required in a player's
// initial (full) state; later updates may carry a subset (see MergeDelta).
type Timing struct {
	// StaticDelayMs shifts playback later to compensate for downstream
	// hardware latency beyond the audio port (0–5000). The server applies it
	// separately when computing send-ahead — clients do not fold it into the
	// two fields below.
	StaticDelayMs int
	// RequiredLeadTimeMs is the startup lead a player needs so the first
	// chunk is not cut off (codec init, decode warmup, DAC latency). A hint:
	// the server may grant less.
	RequiredLeadTimeMs int
	// MinBufferMs is the requested ongoing queued duration during playback,
	// absorbing jitter and decode/playback timing variance.
	MinBufferMs int
	// BufferCapacity is the hard per-player cap, in bytes, on queued
	// compressed audio not yet played (from player@v1_support).
	BufferCapacity int
}

// TimingDelta is a client/state player-object update. A nil field was absent
// from the message and leaves the corresponding Timing value unchanged.
type TimingDelta struct {
	StaticDelayMs      *int
	RequiredLeadTimeMs *int
	MinBufferMs        *int
	BufferCapacity     *int
}

// Validate checks a fully-populated Timing against spec bounds. Use it on a
// player's initial (full) state.
func (t Timing) Validate() error {
	if t.StaticDelayMs < MinStaticDelayMs || t.StaticDelayMs > MaxStaticDelayMs {
		return fmt.Errorf("static_delay_ms %d out of range [%d,%d]", t.StaticDelayMs, MinStaticDelayMs, MaxStaticDelayMs)
	}
	if t.RequiredLeadTimeMs < 0 {
		return fmt.Errorf("required_lead_time_ms %d must be >= 0", t.RequiredLeadTimeMs)
	}
	if t.MinBufferMs < 0 {
		return fmt.Errorf("min_buffer_ms %d must be >= 0", t.MinBufferMs)
	}
	if t.BufferCapacity < 0 {
		return fmt.Errorf("buffer_capacity %d must be >= 0", t.BufferCapacity)
	}
	return nil
}

// MergeDelta applies a client/state delta, retaining the last value of any
// absent field (spec: the server merges each update into existing state).
// static_delay_ms is clamped into range rather than rejected, matching the
// scheduler's tolerance for a misbehaving client.
func (t Timing) MergeDelta(d TimingDelta) Timing {
	out := t
	if d.StaticDelayMs != nil {
		v := *d.StaticDelayMs
		if v < MinStaticDelayMs {
			v = MinStaticDelayMs
		}
		if v > MaxStaticDelayMs {
			v = MaxStaticDelayMs
		}
		out.StaticDelayMs = v
	}
	if d.RequiredLeadTimeMs != nil && *d.RequiredLeadTimeMs >= 0 {
		out.RequiredLeadTimeMs = *d.RequiredLeadTimeMs
	}
	if d.MinBufferMs != nil && *d.MinBufferMs >= 0 {
		out.MinBufferMs = *d.MinBufferMs
	}
	if d.BufferCapacity != nil && *d.BufferCapacity >= 0 {
		out.BufferCapacity = *d.BufferCapacity
	}
	return out
}
