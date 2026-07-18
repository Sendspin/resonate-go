// ABOUTME: Transport framing — binary message-type conventions and the
// ABOUTME: fragmentation of messages exceeding a single Noise frame.
package secure

import "fmt"

// Binary message types owned by the transport layer. Role-specific types
// (player 4-7, artwork 8-11, ...) live with their roles.
const (
	// MsgTypeJSON marks a frame whose payload is a UTF-8 JSON message body.
	MsgTypeJSON byte = 0
	// msgTypeReserved (1) is reserved by the spec for future use.

	// MsgTypeFragmentMore is a non-final fragment frame (bit 0 clear).
	MsgTypeFragmentMore byte = 2
	// MsgTypeFragmentEnd is the final fragment frame (bit 0 set).
	MsgTypeFragmentEnd byte = 3
)

// Fragment payload capacities per frame: every frame's plaintext (including
// its type byte) must fit MaxTransportPlaintext.
const (
	// maxSingleFramePayload is the largest payload that may travel
	// unfragmented: type byte + payload ≤ MaxTransportPlaintext. This works
	// out to the spec's 65 535 − 16 − 1 = 65 518 bytes.
	maxSingleFramePayload = MaxTransportPlaintext - 1
	// maxOpeningFragmentData accounts for the [2][orig_type] prefix.
	maxOpeningFragmentData = MaxTransportPlaintext - 2
	// maxContinuationData accounts for the [2] or [3] prefix.
	maxContinuationData = MaxTransportPlaintext - 1
)

// Fragment splits a message (type + payload) into transport-frame plaintexts.
// A message that fits a single frame is returned as one [type][payload] frame
// (the spec forbids fragmenting messages that fit). Larger messages become an
// opening fragment-more frame carrying orig_type, continuation fragment-more
// frames, and a closing fragment-end frame.
func Fragment(msgType byte, payload []byte) [][]byte {
	if len(payload) <= maxSingleFramePayload {
		frame := make([]byte, 0, 1+len(payload))
		frame = append(frame, msgType)
		frame = append(frame, payload...)
		return [][]byte{frame}
	}

	var frames [][]byte

	// Opening frame: [2][orig_type][data]
	n := min(len(payload), maxOpeningFragmentData)
	opening := make([]byte, 0, 2+n)
	opening = append(opening, MsgTypeFragmentMore, msgType)
	opening = append(opening, payload[:n]...)
	frames = append(frames, opening)
	rest := payload[n:]

	// Continuations while more remains than the closing frame can carry; the
	// remainder is never empty here (payload > maxSingleFramePayload
	// guarantees at least 2 bytes past the opening frame), so the closing
	// fragment-end always carries data.
	for len(rest) > maxContinuationData {
		cont := make([]byte, 0, 1+maxContinuationData)
		cont = append(cont, MsgTypeFragmentMore)
		cont = append(cont, rest[:maxContinuationData]...)
		frames = append(frames, cont)
		rest = rest[maxContinuationData:]
	}

	closing := make([]byte, 0, 1+len(rest))
	closing = append(closing, MsgTypeFragmentEnd)
	closing = append(closing, rest...)
	frames = append(frames, closing)
	return frames
}

// DefaultMaxMessageSize bounds reassembled message size. The spec does not
// set a limit; this guards against a peer streaming fragments forever.
const DefaultMaxMessageSize = 32 << 20 // 32 MiB

// Reassembler is the receive-side fragmentation state machine: one
// reassembly buffer and the in-flight orig_type, per spec. Not safe for
// concurrent use; the connection read loop owns it.
type Reassembler struct {
	maxSize  int
	inFlight bool
	origType byte
	buf      []byte
}

// NewReassembler creates a Reassembler; maxSize ≤ 0 selects
// DefaultMaxMessageSize.
func NewReassembler(maxSize int) *Reassembler {
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageSize
	}
	return &Reassembler{maxSize: maxSize}
}

// Feed processes one decrypted frame plaintext. For unfragmented frames it
// returns the message immediately; for fragment frames it accumulates and
// returns done=false until the fragment-end arrives. Any protocol violation
// returns an error, which is terminal for the connection.
func (r *Reassembler) Feed(frame []byte) (msgType byte, payload []byte, done bool, err error) {
	if len(frame) == 0 {
		return 0, nil, false, fmt.Errorf("empty transport frame")
	}
	t, data := frame[0], frame[1:]

	switch t {
	case MsgTypeFragmentMore:
		if !r.inFlight {
			// Opening frame carries orig_type in byte 1.
			if len(data) == 0 {
				return 0, nil, false, fmt.Errorf("opening fragment frame missing orig_type")
			}
			r.inFlight = true
			r.origType = data[0]
			data = data[1:]
		}
		if err := r.grow(data); err != nil {
			return 0, nil, false, err
		}
		return 0, nil, false, nil

	case MsgTypeFragmentEnd:
		if !r.inFlight {
			return 0, nil, false, fmt.Errorf("fragment-end with no fragmented message in flight")
		}
		if err := r.grow(data); err != nil {
			return 0, nil, false, err
		}
		msgType, payload = r.origType, r.buf
		r.reset()
		return msgType, payload, true, nil

	default:
		if r.inFlight {
			// Spec: only one message in flight across the connection; the
			// sender must close a fragmented message before sending another.
			return 0, nil, false, fmt.Errorf("frame type %d received mid-fragmentation", t)
		}
		return t, data, true, nil
	}
}

func (r *Reassembler) grow(data []byte) error {
	if len(r.buf)+len(data) > r.maxSize {
		r.reset()
		return fmt.Errorf("fragmented message exceeds %d bytes", r.maxSize)
	}
	r.buf = append(r.buf, data...)
	return nil
}

func (r *Reassembler) reset() {
	r.inFlight = false
	r.origType = 0
	r.buf = nil
}
