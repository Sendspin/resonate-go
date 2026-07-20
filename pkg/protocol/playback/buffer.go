// ABOUTME: Per-member send-ahead buffer accounting — tracks bytes queued but
// ABOUTME: not yet played so a player's buffer_capacity is never exceeded.
package playback

// DefaultMaxBufferedUS caps a member's queued duration regardless of byte
// capacity. It matches aiosendspin: even a tiny codec byte rate never lets the
// server run more than this far ahead.
const DefaultMaxBufferedUS int64 = 30_000_000

// queued records one sent-but-unplayed chunk: when its playback ends, how many
// bytes it cost the member's buffer, and how long it plays.
type queued struct {
	endUS      int64
	bytes      int
	durationUS int64
}

// BufferTracker tracks the audio a single member has queued (sent ahead but not
// yet played) so the server never exceeds that member's buffer_capacity byte
// cap or the duration ceiling. A group's audio loop calls Prune once per tick,
// then CanQueue before each send and Register after. It is owned by one
// goroutine (the audio loop) and needs no internal synchronization.
type BufferTracker struct {
	ring  []queued
	head  int
	count int

	bufferedBytes int
	bufferedUS    int64

	capacityBytes int
	maxUS         int64
}

// NewBufferTracker creates a tracker bounded by capacityBytes (the member's
// buffer_capacity). A non-positive capacity means "unbounded by bytes"; the
// duration ceiling still applies.
func NewBufferTracker(capacityBytes int) *BufferTracker {
	return &BufferTracker{
		ring:          make([]queued, 64),
		capacityBytes: capacityBytes,
		maxUS:         DefaultMaxBufferedUS,
	}
}

// SetCapacity updates the byte cap, e.g. after a client/state delta revises
// buffer_capacity. Already-queued audio is unaffected; the new cap governs
// subsequent CanQueue decisions.
func (t *BufferTracker) SetCapacity(capacityBytes int) { t.capacityBytes = capacityBytes }

// Prune drops every chunk whose playback has finished as of nowUS, freeing its
// bytes back to the buffer. Call once per audio tick before CanQueue.
func (t *BufferTracker) Prune(nowUS int64) {
	for t.count > 0 {
		e := t.ring[t.head]
		if e.endUS > nowUS {
			break
		}
		t.bufferedBytes -= e.bytes
		t.bufferedUS -= e.durationUS
		t.head = (t.head + 1) % len(t.ring)
		t.count--
	}
}

// CanQueue reports whether a chunk of the given size and duration fits without
// exceeding the member's byte cap or the duration ceiling. A non-positive byte
// capacity disables the byte check (duration ceiling still applies).
func (t *BufferTracker) CanQueue(bytes int, durationUS int64) bool {
	if t.capacityBytes > 0 && t.bufferedBytes+bytes > t.capacityBytes {
		return false
	}
	return t.bufferedUS+durationUS <= t.maxUS
}

// Register records a chunk as queued. Call it after a successful send; endUS is
// the chunk's playback-end time (its timestamp + duration).
func (t *BufferTracker) Register(endUS int64, bytes int, durationUS int64) {
	if t.count == len(t.ring) {
		t.grow()
	}
	t.ring[(t.head+t.count)%len(t.ring)] = queued{endUS: endUS, bytes: bytes, durationUS: durationUS}
	t.count++
	t.bufferedBytes += bytes
	t.bufferedUS += durationUS
}

// BufferedBytes returns the bytes currently queued for the member.
func (t *BufferTracker) BufferedBytes() int { return t.bufferedBytes }

// BufferedUS returns the duration currently queued for the member.
func (t *BufferTracker) BufferedUS() int64 { return t.bufferedUS }

func (t *BufferTracker) grow() {
	bigger := make([]queued, len(t.ring)*2)
	for i := 0; i < t.count; i++ {
		bigger[i] = t.ring[(t.head+i)%len(t.ring)]
	}
	t.ring = bigger
	t.head = 0
}
