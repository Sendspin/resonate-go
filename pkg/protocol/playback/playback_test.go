// ABOUTME: Table tests for the timing delta-merge and the send-ahead math,
// ABOUTME: anchored to the spec's Server-behavior rules.
package playback

import "testing"

func ptr(i int) *int { return &i }

func TestTiming_MergeDelta(t *testing.T) {
	base := Timing{StaticDelayMs: 100, RequiredLeadTimeMs: 300, MinBufferMs: 200, BufferCapacity: 1 << 20}

	// Absent fields retain their previous values.
	got := base.MergeDelta(TimingDelta{MinBufferMs: ptr(250)})
	if got.MinBufferMs != 250 || got.StaticDelayMs != 100 || got.RequiredLeadTimeMs != 300 || got.BufferCapacity != 1<<20 {
		t.Errorf("partial merge = %+v", got)
	}

	// static_delay_ms clamps rather than rejecting.
	got = base.MergeDelta(TimingDelta{StaticDelayMs: ptr(9000)})
	if got.StaticDelayMs != MaxStaticDelayMs {
		t.Errorf("clamp high = %d, want %d", got.StaticDelayMs, MaxStaticDelayMs)
	}
	got = base.MergeDelta(TimingDelta{StaticDelayMs: ptr(-5)})
	if got.StaticDelayMs != MinStaticDelayMs {
		t.Errorf("clamp low = %d, want %d", got.StaticDelayMs, MinStaticDelayMs)
	}

	// A full delta replaces everything.
	full := base.MergeDelta(TimingDelta{
		StaticDelayMs: ptr(0), RequiredLeadTimeMs: ptr(500), MinBufferMs: ptr(400), BufferCapacity: ptr(2 << 20),
	})
	if full != (Timing{StaticDelayMs: 0, RequiredLeadTimeMs: 500, MinBufferMs: 400, BufferCapacity: 2 << 20}) {
		t.Errorf("full merge = %+v", full)
	}
}

func TestTiming_Validate(t *testing.T) {
	ok := Timing{StaticDelayMs: 5000, RequiredLeadTimeMs: 0, MinBufferMs: 0, BufferCapacity: 0}
	if err := ok.Validate(); err != nil {
		t.Errorf("boundary-valid timing rejected: %v", err)
	}
	for _, bad := range []Timing{
		{StaticDelayMs: 5001},
		{StaticDelayMs: -1},
		{RequiredLeadTimeMs: -1},
		{MinBufferMs: -1},
		{BufferCapacity: -1},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("invalid timing accepted: %+v", bad)
		}
	}
}

func TestPerPlayerSendAhead(t *testing.T) {
	cases := []struct {
		name string
		t    Timing
		kind SourceKind
		want int
	}{
		// Live: baseline min_buffer_ms + static_delay_ms; required lead ignored.
		{"live ignores lead", Timing{MinBufferMs: 200, RequiredLeadTimeMs: 800, StaticDelayMs: 50}, SourceLive, 250},
		// Buffered: extend toward required_lead_time_ms when larger.
		{"buffered extends to lead", Timing{MinBufferMs: 200, RequiredLeadTimeMs: 800, StaticDelayMs: 50}, SourceBuffered, 850},
		// Buffered but min_buffer already exceeds lead: stays at min_buffer.
		{"buffered keeps larger min_buffer", Timing{MinBufferMs: 900, RequiredLeadTimeMs: 400, StaticDelayMs: 0}, SourceBuffered, 900},
		// Zero static delay.
		{"no static delay", Timing{MinBufferMs: 300, RequiredLeadTimeMs: 300, StaticDelayMs: 0}, SourceLive, 300},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PerPlayerSendAheadMs(tc.t, tc.kind); got != tc.want {
				t.Errorf("PerPlayerSendAheadMs = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestGroupSendAhead_MaxAcrossMembers(t *testing.T) {
	players := []Timing{
		{MinBufferMs: 200, StaticDelayMs: 0},   // 200
		{MinBufferMs: 150, StaticDelayMs: 300}, // 450  ← max
		{MinBufferMs: 400, StaticDelayMs: 0},   // 400
	}
	if got := GroupSendAheadMs(players, SourceLive); got != 450 {
		t.Errorf("group send-ahead = %d, want 450 (max member)", got)
	}
	if got := GroupSendAheadMs(nil, SourceLive); got != 0 {
		t.Errorf("empty group send-ahead = %d, want 0", got)
	}

	// A high static_delay player raises the common send-ahead so its lead is met.
	players = append(players, Timing{MinBufferMs: 100, StaticDelayMs: 5000}) // 5100
	if got := GroupSendAheadMs(players, SourceLive); got != 5100 {
		t.Errorf("group send-ahead with high-delay member = %d, want 5100", got)
	}
}

func TestMaxQueuedDuration_BufferCapacityCap(t *testing.T) {
	// 48 kHz stereo 16-bit PCM = 192000 bytes/sec.
	rate := PCMByteRatePerSec(48000, 2, 16)
	if rate != 192000 {
		t.Fatalf("PCM byte rate = %d, want 192000", rate)
	}
	// 1 MB / 192000 B/s ≈ 5461 ms.
	if got := MaxQueuedDurationMs(1<<20, rate); got != 5461 {
		t.Errorf("max queued = %d ms, want 5461", got)
	}
	// Degenerate inputs.
	if MaxQueuedDurationMs(0, rate) != 0 || MaxQueuedDurationMs(1<<20, 0) != 0 {
		t.Error("degenerate inputs should yield 0")
	}
}

func TestEffectiveQueued_HiResPCMUnderrunsCapacity(t *testing.T) {
	// 192 kHz stereo 24-bit PCM = 1,152,000 bytes/sec — a small buffer_capacity
	// cannot hold min_buffer_ms, so the effective queued duration is forced
	// below the request (the spec's live-stream caveat).
	rate := PCMByteRatePerSec(192000, 2, 24)
	if rate != 1152000 {
		t.Fatalf("hi-res PCM byte rate = %d", rate)
	}
	tm := Timing{MinBufferMs: 500, BufferCapacity: 256 << 10} // 262144 B → ~227 ms
	capMs := MaxQueuedDurationMs(tm.BufferCapacity, rate)
	if capMs >= tm.MinBufferMs {
		t.Fatalf("test setup: cap %d should be below min_buffer %d", capMs, tm.MinBufferMs)
	}
	if !BufferCapacityLimits(tm, rate) {
		t.Error("BufferCapacityLimits should report a limit here")
	}
	if got := EffectiveQueuedMs(tm, rate); got != capMs {
		t.Errorf("effective queued = %d, want %d (capped)", got, capMs)
	}

	// A generous buffer at a modest rate is not limited: effective == request.
	cdRate := PCMByteRatePerSec(44100, 2, 16) // 176400 B/s
	roomy := Timing{MinBufferMs: 500, BufferCapacity: 1 << 20}
	if BufferCapacityLimits(roomy, cdRate) {
		t.Error("roomy buffer should not be limited")
	}
	if got := EffectiveQueuedMs(roomy, cdRate); got != 500 {
		t.Errorf("effective queued = %d, want the requested 500", got)
	}
}
