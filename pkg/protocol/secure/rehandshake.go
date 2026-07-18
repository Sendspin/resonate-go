// ABOUTME: In-band re-handshake — rerunning KKpsk2 inside the encrypted
// ABOUTME: channel to swap session keys (post-pairing promotion, key rotation).
package secure

import (
	"encoding/json"
	"fmt"
)

// RehandshakeInitiate reruns the Noise handshake from the server side inside
// the current transport channel, swapping to psk. Per spec: client/init and
// server/init are not re-sent; identity, peer, and suite carry over; the new
// prologue is the prior handshake's hash h; the two noise/handshake messages
// travel as encrypted JSON frames. No other messages may flow during the
// exchange — the caller must be at a quiescent point in the conversation.
func (c *Conn) RehandshakeInitiate(psk PSK) error {
	init, err := NewInitiator(InitiatorConfig{
		Identity:      c.identity,
		PeerPublicKey: c.peerPub,
		Suite:         c.suite,
		Prologue:      c.sess.HandshakeHash(),
		PSK:           psk,
	})
	if err != nil {
		return err
	}
	msg1, err := init.Message1(psk.ID())
	if err != nil {
		return err
	}
	env, err := EncodeNoiseHandshake(msg1)
	if err != nil {
		return err
	}
	if err := c.WriteMessage(MsgTypeJSON, env); err != nil {
		return fmt.Errorf("send rehandshake message 1: %w", err)
	}

	// Messages the peer sent under the old keys before it observed our
	// message 1 may legitimately arrive first (in-order delivery); skip
	// until the noise/handshake response, bounded so a peer that never
	// responds cannot spin us forever.
	const maxSkipped = 64
	for i := 0; ; i++ {
		if i == maxSkipped {
			return fmt.Errorf("no noise/handshake response within %d messages", maxSkipped)
		}
		msgType, payload, err := c.ReadMessage()
		if err != nil {
			return fmt.Errorf("read rehandshake message 2: %w", err)
		}
		if msgType != MsgTypeJSON || !isNoiseEnvelope(payload) {
			continue // pre-rehandshake message under the old keys
		}
		msg2, err := ParseNoiseHandshake(payload)
		if err != nil {
			return err
		}
		sess, err := init.Finish(msg2)
		if err != nil {
			return err
		}
		c.swapSession(sess)
		return nil
	}
}

// isNoiseEnvelope reports whether a JSON control payload is a
// noise/handshake message.
func isNoiseEnvelope(raw []byte) bool {
	var env struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(raw, &env) == nil && env.Type == "noise/handshake"
}

// RehandshakeRespond completes a re-handshake from the client side. The
// caller has already read the first noise/handshake envelope from the
// channel (message1Envelope is its raw JSON); selectPSK maps the announced
// psk_id to the new PSK.
func (c *Conn) RehandshakeRespond(message1Envelope []byte, selectPSK func(pskID string) (PSK, bool)) error {
	msg1, err := ParseNoiseHandshake(message1Envelope)
	if err != nil {
		return err
	}
	resp, err := NewResponder(ResponderConfig{
		Identity:      c.identity,
		PeerPublicKey: c.peerPub,
		Suite:         c.suite,
		Prologue:      c.sess.HandshakeHash(),
		SelectPSK:     selectPSK,
	})
	if err != nil {
		return err
	}
	msg2, sess, err := resp.Accept(msg1)
	if err != nil {
		return err
	}
	env, err := EncodeNoiseHandshake(msg2)
	if err != nil {
		return err
	}
	// Message 2 must leave under the OLD keys; swap only after sending.
	if err := c.WriteMessage(MsgTypeJSON, env); err != nil {
		return fmt.Errorf("send rehandshake message 2: %w", err)
	}
	c.swapSession(sess)
	return nil
}

// swapSession installs the new transport keys and resets fragmentation
// state; a fragmented message never spans a re-handshake.
func (c *Conn) swapSession(sess *Session) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.sess = sess
	c.reasm = NewReassembler(c.reasm.maxSize)
}
