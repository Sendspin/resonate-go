// ABOUTME: Tests for transport framing and fragmentation: round trips at
// ABOUTME: boundary sizes, frame caps, and receiver protocol violations.
package secure

import (
	"bytes"
	"math/rand"
	"testing"
)

// reassemble feeds frames through a Reassembler and returns the message.
func reassemble(t *testing.T, frames [][]byte) (byte, []byte) {
	t.Helper()
	r := NewReassembler(0)
	for i, f := range frames {
		msgType, payload, done, err := r.Feed(f)
		if err != nil {
			t.Fatalf("Feed frame %d: %v", i, err)
		}
		if done {
			if i != len(frames)-1 {
				t.Fatalf("message completed at frame %d of %d", i+1, len(frames))
			}
			return msgType, payload
		}
	}
	t.Fatal("frames exhausted without completing a message")
	return 0, nil
}

func TestFragment_SmallMessageSingleFrame(t *testing.T) {
	payload := []byte(`{"type":"server/hello","payload":{"name":"x"}}`)
	frames := Fragment(MsgTypeJSON, payload)
	if len(frames) != 1 {
		t.Fatalf("small message produced %d frames, want 1", len(frames))
	}
	if frames[0][0] != MsgTypeJSON {
		t.Errorf("frame type = %d, want %d", frames[0][0], MsgTypeJSON)
	}
	msgType, back := reassemble(t, frames)
	if msgType != MsgTypeJSON || !bytes.Equal(back, payload) {
		t.Error("single-frame round trip mismatch")
	}
}

func TestFragment_BoundarySizes(t *testing.T) {
	cases := []struct {
		size       int
		wantFrames int
	}{
		{0, 1},
		{1, 1},
		{maxSingleFramePayload, 1},     // largest unfragmented message
		{maxSingleFramePayload + 1, 2}, // smallest fragmented message
		{maxOpeningFragmentData + maxContinuationData, 2},
		{maxOpeningFragmentData + maxContinuationData + 1, 3},
	}
	for _, tc := range cases {
		payload := bytes.Repeat([]byte{0xAB}, tc.size)
		frames := Fragment(0x08, payload) // artwork channel 0
		if len(frames) != tc.wantFrames {
			t.Errorf("size %d: %d frames, want %d", tc.size, len(frames), tc.wantFrames)
		}
		for i, f := range frames {
			if len(f) > MaxTransportPlaintext {
				t.Errorf("size %d frame %d: %d bytes exceeds transport cap %d",
					tc.size, i, len(f), MaxTransportPlaintext)
			}
		}
		msgType, back := reassemble(t, frames)
		if msgType != 0x08 || !bytes.Equal(back, payload) {
			t.Errorf("size %d: round trip mismatch", tc.size)
		}
	}
}

func TestFragment_LargeMessageWireShape(t *testing.T) {
	payload := make([]byte, 200_000) // typical artwork image size
	rnd := rand.New(rand.NewSource(1))
	rnd.Read(payload)

	frames := Fragment(0x09, payload)
	if len(frames) < 4 {
		t.Fatalf("200kB message produced only %d frames", len(frames))
	}
	if frames[0][0] != MsgTypeFragmentMore || frames[0][1] != 0x09 {
		t.Errorf("opening frame prefix = [%d %d], want [2 9]", frames[0][0], frames[0][1])
	}
	for i := 1; i < len(frames)-1; i++ {
		if frames[i][0] != MsgTypeFragmentMore {
			t.Errorf("continuation frame %d type = %d, want 2", i, frames[i][0])
		}
	}
	last := frames[len(frames)-1]
	if last[0] != MsgTypeFragmentEnd {
		t.Errorf("closing frame type = %d, want 3", last[0])
	}
	if len(last) < 2 {
		t.Error("closing frame carries no data")
	}

	msgType, back := reassemble(t, frames)
	if msgType != 0x09 || !bytes.Equal(back, payload) {
		t.Error("large round trip mismatch")
	}
}

func TestFragment_ThroughEncryptedSession(t *testing.T) {
	serverSess, clientSess := runHandshake(t, SuiteAESGCM, SentinelPSK(), sentinelSelector)

	payload := make([]byte, 150_000)
	rand.New(rand.NewSource(2)).Read(payload)

	r := NewReassembler(0)
	var gotType byte
	var got []byte
	for _, frame := range Fragment(0x0A, payload) {
		ct, err := serverSess.Encrypt(frame)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		pt, err := clientSess.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		msgType, p, done, err := r.Feed(pt)
		if err != nil {
			t.Fatalf("Feed: %v", err)
		}
		if done {
			gotType, got = msgType, p
		}
	}
	if gotType != 0x0A || !bytes.Equal(got, payload) {
		t.Error("fragmented message did not survive the encrypted channel")
	}
}

func TestReassembler_Violations(t *testing.T) {
	t.Run("fragment-end without start", func(t *testing.T) {
		r := NewReassembler(0)
		if _, _, _, err := r.Feed([]byte{MsgTypeFragmentEnd, 0x01}); err == nil {
			t.Error("orphan fragment-end accepted")
		}
	})

	t.Run("non-fragment frame mid-flight", func(t *testing.T) {
		r := NewReassembler(0)
		if _, _, _, err := r.Feed([]byte{MsgTypeFragmentMore, MsgTypeJSON, 0x01}); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := r.Feed([]byte{0x04, 0x00}); err == nil {
			t.Error("interleaved non-fragment frame accepted")
		}
	})

	t.Run("empty frame", func(t *testing.T) {
		r := NewReassembler(0)
		if _, _, _, err := r.Feed(nil); err == nil {
			t.Error("empty frame accepted")
		}
	})

	t.Run("opening frame without orig_type", func(t *testing.T) {
		r := NewReassembler(0)
		if _, _, _, err := r.Feed([]byte{MsgTypeFragmentMore}); err == nil {
			t.Error("opening fragment without orig_type accepted")
		}
	})

	t.Run("oversized reassembly", func(t *testing.T) {
		r := NewReassembler(16)
		if _, _, _, err := r.Feed(append([]byte{MsgTypeFragmentMore, MsgTypeJSON}, make([]byte, 10)...)); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := r.Feed(append([]byte{MsgTypeFragmentEnd}, make([]byte, 10)...)); err == nil {
			t.Error("reassembly over the size limit accepted")
		}
	})

	t.Run("usable after violation reset", func(t *testing.T) {
		r := NewReassembler(0)
		if _, _, _, err := r.Feed([]byte{MsgTypeFragmentEnd, 0x01}); err == nil {
			t.Fatal("orphan fragment-end accepted")
		}
		msgType, payload, done, err := r.Feed([]byte{MsgTypeJSON, '{', '}'})
		if err != nil || !done || msgType != MsgTypeJSON || string(payload) != "{}" {
			t.Error("reassembler unusable after a violation")
		}
	})
}
