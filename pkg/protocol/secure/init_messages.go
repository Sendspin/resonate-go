// ABOUTME: The cleartext connection preamble — client/init, server/init, and
// ABOUTME: the noise/handshake envelope, with exact-byte handling for the prologue.
package secure

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// CoreVersion is the version of the core message format this implementation
// speaks; client/init and server/init both carry it and it must be 1.
const CoreVersion = 1

// ClientInit is the payload of the first message on every connection.
type ClientInit struct {
	ClientID string `json:"client_id"`
	Version  int    `json:"version"`
	Suite    Suite  `json:"suite"`
}

// ServerInit is the payload of the server's cleartext response.
type ServerInit struct {
	ServerID string `json:"server_id"`
	Version  int    `json:"version"`
}

// envelope is the {type, payload} wrapper shared by all JSON messages. The
// prologue binds the exact wire bytes, so encode functions return the bytes
// that must be both transmitted and fed to the handshake verbatim.
type envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

func encodeEnvelope(msgType string, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal %s payload: %w", msgType, err)
	}
	out, err := json.Marshal(envelope{Type: msgType, Payload: raw})
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", msgType, err)
	}
	return out, nil
}

func decodeEnvelope(raw []byte, wantType string, payload any) error {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("malformed message: %w", err)
	}
	if env.Type != wantType {
		return fmt.Errorf("expected %s, got %q", wantType, env.Type)
	}
	if err := json.Unmarshal(env.Payload, payload); err != nil {
		return fmt.Errorf("malformed %s payload: %w", wantType, err)
	}
	return nil
}

// EncodeClientInit produces the exact wire bytes of a client/init message.
func EncodeClientInit(ci ClientInit) ([]byte, error) {
	if err := ci.validate(); err != nil {
		return nil, err
	}
	return encodeEnvelope("client/init", ci)
}

// ParseClientInit validates and decodes client/init wire bytes. Callers must
// retain the raw bytes for the prologue.
func ParseClientInit(raw []byte) (ClientInit, error) {
	var ci ClientInit
	if err := decodeEnvelope(raw, "client/init", &ci); err != nil {
		return ClientInit{}, err
	}
	if err := ci.validate(); err != nil {
		return ClientInit{}, err
	}
	return ci, nil
}

func (ci ClientInit) validate() error {
	if _, err := ParseID(ci.ClientID); err != nil {
		return fmt.Errorf("client/init client_id: %w", err)
	}
	if ci.Version != CoreVersion {
		return fmt.Errorf("client/init version %d unsupported (want %d)", ci.Version, CoreVersion)
	}
	if !ci.Suite.Valid() {
		return fmt.Errorf("client/init: unknown cipher suite %q", string(ci.Suite))
	}
	return nil
}

// EncodeServerInit produces the exact wire bytes of a server/init message.
func EncodeServerInit(si ServerInit) ([]byte, error) {
	if err := si.validate(); err != nil {
		return nil, err
	}
	return encodeEnvelope("server/init", si)
}

// ParseServerInit validates and decodes server/init wire bytes. Callers must
// retain the raw bytes for the prologue.
func ParseServerInit(raw []byte) (ServerInit, error) {
	var si ServerInit
	if err := decodeEnvelope(raw, "server/init", &si); err != nil {
		return ServerInit{}, err
	}
	if err := si.validate(); err != nil {
		return ServerInit{}, err
	}
	return si, nil
}

func (si ServerInit) validate() error {
	if _, err := ParseID(si.ServerID); err != nil {
		return fmt.Errorf("server/init server_id: %w", err)
	}
	if si.Version != CoreVersion {
		return fmt.Errorf("server/init version %d unsupported (want %d)", si.Version, CoreVersion)
	}
	return nil
}

// Prologue builds the Noise prologue: the exact wire bytes of client/init
// followed by the exact wire bytes of server/init, concatenated.
func Prologue(clientInitRaw, serverInitRaw []byte) []byte {
	return bytes.Join([][]byte{clientInitRaw, serverInitRaw}, nil)
}

// EncodeNoiseHandshake wraps raw Noise handshake bytes in the
// noise/handshake envelope (base64url data field).
func EncodeNoiseHandshake(noiseMsg []byte) ([]byte, error) {
	return encodeEnvelope("noise/handshake", map[string]string{
		"data": b64.EncodeToString(noiseMsg),
	})
}

// ParseNoiseHandshake unwraps a noise/handshake envelope back to the raw
// Noise handshake bytes.
func ParseNoiseHandshake(raw []byte) ([]byte, error) {
	var payload struct {
		Data string `json:"data"`
	}
	if err := decodeEnvelope(raw, "noise/handshake", &payload); err != nil {
		return nil, err
	}
	msg, err := b64.DecodeString(payload.Data)
	if err != nil {
		return nil, fmt.Errorf("noise/handshake data is not valid base64url: %w", err)
	}
	return msg, nil
}
