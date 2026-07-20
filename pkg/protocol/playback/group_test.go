// ABOUTME: Tests for the playback Group — membership, group send-ahead, and
// ABOUTME: buffer-paced, availability-gated fan-out of audio chunks.
package playback

import (
	"errors"
	"testing"
)

// recordWriter captures every chunk written and can be forced to fail.
type recordWriter struct {
	writes [][]byte // each entry is [msgType][body]
	fail   error
}

func (w *recordWriter) WriteMessage(msgType byte, payload []byte) error {
	if w.fail != nil {
		return w.fail
	}
	frame := append([]byte{msgType}, payload...)
	w.writes = append(w.writes, frame)
	return nil
}

func timing(minBuf, lead, staticDelay, cap int) Timing {
	return Timing{MinBufferMs: minBuf, RequiredLeadTimeMs: lead, StaticDelayMs: staticDelay, BufferCapacity: cap}
}

// constPayload returns the same payload for every member.
func constPayload(b []byte) func(*Member) []byte {
	return func(*Member) []byte { return b }
}

func TestGroup_AddRemoveLen(t *testing.T) {
	g := NewGroup(SourceLive)
	g.Add("a", &recordWriter{}, timing(100, 0, 0, 0), 0)
	g.Add("b", &recordWriter{}, timing(100, 0, 0, 0), 0)
	if g.Len() != 2 {
		t.Fatalf("len = %d, want 2", g.Len())
	}
	g.Remove("a")
	if g.Len() != 1 {
		t.Fatalf("len = %d, want 1 after remove", g.Len())
	}
	g.Remove("missing") // no-op
	if g.Len() != 1 {
		t.Fatalf("len = %d, want 1", g.Len())
	}
}

func TestGroup_SendAheadMs_AvailableOnly(t *testing.T) {
	g := NewGroup(SourceLive)
	// a: 100ms min buffer; b: 250ms min buffer but unavailable.
	g.Add("a", &recordWriter{}, timing(100, 0, 0, 0), 0)
	g.Add("b", &recordWriter{}, timing(250, 0, 0, 0), 0)
	g.SetAvailable("a", true)

	if sa := g.SendAheadMs(); sa != 100 {
		t.Errorf("send-ahead = %d, want 100 (only a available)", sa)
	}
	g.SetAvailable("b", true)
	if sa := g.SendAheadMs(); sa != 250 {
		t.Errorf("send-ahead = %d, want 250 (b now available, max)", sa)
	}
}

func TestGroup_SendAheadMs_EmptyOrNoneAvailable(t *testing.T) {
	g := NewGroup(SourceLive)
	if sa := g.SendAheadMs(); sa != 0 {
		t.Errorf("empty group send-ahead = %d, want 0", sa)
	}
	g.Add("a", &recordWriter{}, timing(100, 0, 0, 0), 0)
	if sa := g.SendAheadMs(); sa != 0 {
		t.Errorf("no-available send-ahead = %d, want 0", sa)
	}
}

func TestGroup_Broadcast_AvailableOnly(t *testing.T) {
	wa, wb := &recordWriter{}, &recordWriter{}
	g := NewGroup(SourceLive)
	g.Add("a", wa, timing(100, 0, 0, 0), 0)
	g.Add("b", wb, timing(100, 0, 0, 0), 0)
	g.SetAvailable("a", true) // b stays unavailable

	audio := []byte{0xaa, 0xbb}
	res := g.Broadcast(0, 5_000_000, 20_000, constPayload(audio))
	if len(res) != 1 || res[0].MemberID != "a" || !res[0].Sent {
		t.Fatalf("results = %+v, want single sent to a", res)
	}
	if len(wa.writes) != 1 {
		t.Fatalf("a got %d writes, want 1", len(wa.writes))
	}
	if len(wb.writes) != 0 {
		t.Fatalf("unavailable b got %d writes, want 0", len(wb.writes))
	}
	// Verify the wire framing: [type=4][8-byte ts][audio].
	frame := wa.writes[0]
	if frame[0] != PlayerAudioMsgType {
		t.Errorf("msg type = %d, want %d", frame[0], PlayerAudioMsgType)
	}
	ts, payload, err := ParseAudioChunk(frame[1:])
	if err != nil {
		t.Fatalf("parse chunk: %v", err)
	}
	if ts != 5_000_000 {
		t.Errorf("chunk ts = %d, want 5000000", ts)
	}
	if string(payload) != string(audio) {
		t.Errorf("payload = %v, want %v", payload, audio)
	}
}

func TestGroup_Broadcast_PerMemberPayloadAndSkip(t *testing.T) {
	wa, wb := &recordWriter{}, &recordWriter{}
	g := NewGroup(SourceLive)
	g.Add("a", wa, timing(100, 0, 0, 0), 0)
	g.Add("b", wb, timing(100, 0, 0, 0), 0)
	g.SetAvailable("a", true)
	g.SetAvailable("b", true)

	// a gets bytes, b is skipped (nil payload, e.g. codec not ready).
	res := g.Broadcast(0, 1_000, 20_000, func(m *Member) []byte {
		if m.ID == "a" {
			return []byte{0x01}
		}
		return nil
	})
	if len(res) != 1 || res[0].MemberID != "a" {
		t.Fatalf("results = %+v, want only a", res)
	}
	if len(wa.writes) != 1 || len(wb.writes) != 0 {
		t.Fatalf("writes a=%d b=%d, want 1 and 0", len(wa.writes), len(wb.writes))
	}
}

func TestGroup_Broadcast_BufferCapacityBackpressure(t *testing.T) {
	w := &recordWriter{}
	g := NewGroup(SourceLive)
	// buffer_capacity = 5 bytes; codec byte rate irrelevant to the byte cap.
	g.Add("a", w, timing(100, 0, 0, 5), 0)
	g.SetAvailable("a", true)

	payload := []byte{0x01, 0x02, 0x03} // 3 bytes; two won't fit in 5.
	// First chunk fits (3 <= 5) and plays 0..20ms.
	res1 := g.Broadcast(0, 0, 20_000, constPayload(payload))
	if len(res1) != 1 || !res1[0].Sent {
		t.Fatalf("chunk 1 = %+v, want sent", res1)
	}
	// Second chunk at nowUS=0 still queued (3+3=6 > 5) → backpressure.
	res2 := g.Broadcast(0, 20_000, 20_000, constPayload(payload))
	if len(res2) != 1 || !res2[0].Backpressure {
		t.Fatalf("chunk 2 = %+v, want backpressure", res2)
	}
	if len(w.writes) != 1 {
		t.Fatalf("writes = %d, want 1 (second dropped)", len(w.writes))
	}
	// Advance now past the first chunk's end (20ms) so it prunes, freeing room.
	res3 := g.Broadcast(20_000, 40_000, 20_000, constPayload(payload))
	if len(res3) != 1 || !res3[0].Sent {
		t.Fatalf("chunk 3 = %+v, want sent after prune", res3)
	}
	if len(w.writes) != 2 {
		t.Fatalf("writes = %d, want 2", len(w.writes))
	}
}

func TestGroup_Broadcast_WriteErrorReported(t *testing.T) {
	w := &recordWriter{fail: errors.New("broken pipe")}
	g := NewGroup(SourceLive)
	g.Add("a", w, timing(100, 0, 0, 0), 0)
	g.SetAvailable("a", true)

	res := g.Broadcast(0, 0, 20_000, constPayload([]byte{0x01}))
	if len(res) != 1 || res[0].Err == nil {
		t.Fatalf("results = %+v, want a write error", res)
	}
	// A failed write must not count against the buffer.
	if bb := g.members["a"].tracker.BufferedBytes(); bb != 0 {
		t.Errorf("buffered bytes after failed write = %d, want 0", bb)
	}
}

func TestGroup_SetTiming_UpdatesSendAheadAndCapacity(t *testing.T) {
	w := &recordWriter{}
	g := NewGroup(SourceLive)
	g.Add("a", w, timing(100, 0, 0, 5), 0)
	g.SetAvailable("a", true)
	if sa := g.SendAheadMs(); sa != 100 {
		t.Fatalf("send-ahead = %d, want 100", sa)
	}
	g.SetTiming("a", timing(300, 0, 50, 10))
	if sa := g.SendAheadMs(); sa != 350 {
		t.Errorf("send-ahead = %d, want 350 (300 min + 50 static)", sa)
	}
	// New capacity of 10 now admits a 10-byte chunk that 5 would have rejected.
	res := g.Broadcast(0, 0, 20_000, constPayload(make([]byte, 10)))
	if len(res) != 1 || !res[0].Sent {
		t.Errorf("chunk = %+v, want sent under new capacity", res)
	}
}
