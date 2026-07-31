// ABOUTME: Typed spec-v2 core messages (hello, activate, time, goodbye) and
// ABOUTME: the envelope registry used to parse incoming JSON control messages.
package session

import (
	"encoding/json"
	"fmt"
)

// TrustLevel is the trust the client extends to the server on a connection.
type TrustLevel string

const (
	// TrustUser means a pairing record exists for the server.
	TrustUser TrustLevel = "user"
	// TrustNone means no record exists: pairing handshakes and unpaired access.
	TrustNone TrustLevel = "none"
)

// Valid reports whether t is a spec-defined trust level.
func (t TrustLevel) Valid() bool { return t == TrustUser || t == TrustNone }

// ServerHello is the first encrypted message, sent by the server.
type ServerHello struct {
	Name string `json:"name"`
}

// DeviceInfo describes the client device in client/hello.
type DeviceInfo struct {
	ProductName     string `json:"product_name,omitempty"`
	Manufacturer    string `json:"manufacturer,omitempty"`
	SoftwareVersion string `json:"software_version,omitempty"`
	MACAddress      string `json:"mac_address,omitempty"`
}

// AudioFormat is one entry of a player's supported_formats list.
type AudioFormat struct {
	Codec      string `json:"codec"`
	Channels   int    `json:"channels"`
	SampleRate int    `json:"sample_rate"`
	BitDepth   int    `json:"bit_depth"`
}

// PlayerSupport is the player@v1_support object.
type PlayerSupport struct {
	SupportedFormats  []AudioFormat `json:"supported_formats"`
	BufferCapacity    int           `json:"buffer_capacity"`
	SupportedCommands []string      `json:"supported_commands"`
}

// SourceSupport is the source@v1_support object.
type SourceSupport struct {
	Features *SourceFeatures `json:"features,omitempty"`
}

// SourceFeatures holds optional source feature hints.
type SourceFeatures struct {
	LineSense bool `json:"line_sense,omitempty"`
}

// ArtworkChannel is one entry of the artwork@v1_support channels list.
type ArtworkChannel struct {
	Source      string `json:"source"`
	Format      string `json:"format"`
	MediaWidth  int    `json:"media_width"`
	MediaHeight int    `json:"media_height"`
}

// ArtworkSupport is the artwork@v1_support object.
type ArtworkSupport struct {
	Channels []ArtworkChannel `json:"channels"`
}

// SpectrumConfig configures visualizer spectrum binning.
type SpectrumConfig struct {
	NDispBins int    `json:"n_disp_bins"`
	Scale     string `json:"scale"`
	FMin      int    `json:"f_min"`
	FMax      int    `json:"f_max"`
}

// VisualizerSupport is the visualizer@v1_support object.
type VisualizerSupport struct {
	Types          []string        `json:"types"`
	BufferCapacity int             `json:"buffer_capacity"`
	RateMax        int             `json:"rate_max"`
	Spectrum       *SpectrumConfig `json:"spectrum,omitempty"`
}

// PairMethodDescriptor is one entry of supported_pair_methods.
type PairMethodDescriptor struct {
	Method       string   `json:"method"`
	OutChannels  []string `json:"out_channels,omitempty"`
	MinPINLength int      `json:"min_pin_length,omitempty"`
	LockedOut    *bool    `json:"locked_out,omitempty"`
}

// UnpairedAccess advertises whether the client admits unpaired servers.
type UnpairedAccess struct {
	Enabled bool `json:"enabled"`
}

// ClientHello is the client's encrypted capability announcement.
type ClientHello struct {
	Name                 string                 `json:"name"`
	DeviceInfo           *DeviceInfo            `json:"device_info,omitempty"`
	TrustLevel           TrustLevel             `json:"trust_level"`
	SupportedRoles       []string               `json:"supported_roles"`
	PlayerSupport        *PlayerSupport         `json:"player@v1_support,omitempty"`
	SourceSupport        *SourceSupport         `json:"source@v1_support,omitempty"`
	ArtworkSupport       *ArtworkSupport        `json:"artwork@v1_support,omitempty"`
	VisualizerSupport    *VisualizerSupport     `json:"visualizer@v1_support,omitempty"`
	SupportedPairMethods []PairMethodDescriptor `json:"supported_pair_methods,omitempty"`
	UnpairedAccess       UnpairedAccess         `json:"unpaired_access"`
}

// Activity is one entry of server/activate's activities set.
type Activity string

const (
	ActivityPlayback   Activity = "playback"
	ActivityPairing    Activity = "pairing"
	ActivityManagement Activity = "management"
)

// Valid reports whether a is a spec-defined activity.
func (a Activity) Valid() bool {
	return a == ActivityPlayback || a == ActivityPairing || a == ActivityManagement
}

// ServerActivate declares the server's current purpose on the connection.
// ActiveRoles uses a pointer to distinguish "omitted, persist previous"
// (nil) from "explicitly empty" (&[]string{}).
type ServerActivate struct {
	Activities         []Activity `json:"activities"`
	ActiveRoles        *[]string  `json:"active_roles,omitempty"`
	SelectedPairMethod string     `json:"selected_pair_method,omitempty"`
}

// ClientTime is the client's clock-sync probe.
type ClientTime struct {
	ClientTransmitted int64 `json:"client_transmitted"`
}

// ServerTime answers a ClientTime with server receive/transmit timestamps.
type ServerTime struct {
	ClientTransmitted int64 `json:"client_transmitted"`
	ServerReceived    int64 `json:"server_received"`
	ServerTransmitted int64 `json:"server_transmitted"`
}

// GoodbyeReason enumerates client/goodbye reasons.
type GoodbyeReason string

const (
	GoodbyeAnotherServer     GoodbyeReason = "another_server"
	GoodbyeShutdown          GoodbyeReason = "shutdown"
	GoodbyeRestart           GoodbyeReason = "restart"
	GoodbyeUserRequest       GoodbyeReason = "user_request"
	GoodbyeUnauthorized      GoodbyeReason = "unauthorized"
	GoodbyePairingRequired   GoodbyeReason = "pairing_required"
	GoodbyeConcurrentAttempt GoodbyeReason = "concurrent_attempt"
	GoodbyeUnpaired          GoodbyeReason = "unpaired"
)

// Valid reports whether r is a spec-defined goodbye reason.
func (r GoodbyeReason) Valid() bool {
	switch r {
	case GoodbyeAnotherServer, GoodbyeShutdown, GoodbyeRestart, GoodbyeUserRequest,
		GoodbyeUnauthorized, GoodbyePairingRequired, GoodbyeConcurrentAttempt, GoodbyeUnpaired:
		return true
	}
	return false
}

// ClientGoodbye announces a graceful client disconnect.
type ClientGoodbye struct {
	Reason GoodbyeReason `json:"reason"`
}

// UnknownMessage carries a message whose type this package does not model.
// Receivers skip these rather than failing, mirroring the spec's
// unknown-field tolerance at the message level.
type UnknownMessage struct {
	Type    string
	Payload json.RawMessage
}

// Envelope mirrors the {type, payload} wrapper of every JSON message.
type Envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// typeOf maps message structs to their wire type strings.
func typeOf(v any) (string, error) {
	switch v.(type) {
	case ServerHello, *ServerHello:
		return "server/hello", nil
	case ClientHello, *ClientHello:
		return "client/hello", nil
	case ServerActivate, *ServerActivate:
		return "server/activate", nil
	case ClientTime, *ClientTime:
		return "client/time", nil
	case ServerTime, *ServerTime:
		return "server/time", nil
	case ClientGoodbye, *ClientGoodbye:
		return "client/goodbye", nil
	case ClientState, *ClientState:
		return "client/state", nil
	case GroupUpdate, *GroupUpdate:
		return "group/update", nil
	case StreamStart, *StreamStart:
		return "stream/start", nil
	case StreamEnd, *StreamEnd:
		return "stream/end", nil
	case ClientCommand, *ClientCommand:
		return "client/command", nil
	case ServerCommand, *ServerCommand:
		return "server/command", nil
	case ClientPairInit, *ClientPairInit:
		return "client/pair-init", nil
	case ServerPairInit, *ServerPairInit:
		return "server/pair-init", nil
	case ServerPairAuth, *ServerPairAuth:
		return "server/pair-auth", nil
	case ClientPairAuth, *ClientPairAuth:
		return "client/pair-auth", nil
	case ServerPairConfirm, *ServerPairConfirm:
		return "server/pair-confirm", nil
	case ClientPairConfirm, *ClientPairConfirm:
		return "client/pair-confirm", nil
	case ClientPairFinalize, *ClientPairFinalize:
		return "client/pair-finalize", nil
	case ServerPairFinalize, *ServerPairFinalize:
		return "server/pair-finalize", nil
	case PairAbort, *PairAbort:
		return "pair/abort", nil
	default:
		return "", fmt.Errorf("unknown message type %T", v)
	}
}

// Marshal wraps a typed message in its envelope and returns the wire bytes.
func Marshal(v any) ([]byte, error) {
	msgType, err := typeOf(v)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal %s payload: %w", msgType, err)
	}
	return json.Marshal(Envelope{Type: msgType, Payload: payload})
}

// Parse decodes wire bytes into the matching typed message, or an
// UnknownMessage for types outside this package's registry.
func Parse(raw []byte) (any, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("malformed message: %w", err)
	}
	var v any
	switch env.Type {
	case "server/hello":
		v = &ServerHello{}
	case "client/hello":
		v = &ClientHello{}
	case "server/activate":
		v = &ServerActivate{}
	case "client/time":
		v = &ClientTime{}
	case "server/time":
		v = &ServerTime{}
	case "client/goodbye":
		v = &ClientGoodbye{}
	case "client/state":
		v = &ClientState{}
	case "group/update":
		v = &GroupUpdate{}
	case "stream/start":
		v = &StreamStart{}
	case "stream/end":
		v = &StreamEnd{}
	case "client/command":
		v = &ClientCommand{}
	case "server/command":
		v = &ServerCommand{}
	case "client/pair-init":
		v = &ClientPairInit{}
	case "server/pair-init":
		v = &ServerPairInit{}
	case "server/pair-auth":
		v = &ServerPairAuth{}
	case "client/pair-auth":
		v = &ClientPairAuth{}
	case "server/pair-confirm":
		v = &ServerPairConfirm{}
	case "client/pair-confirm":
		v = &ClientPairConfirm{}
	case "client/pair-finalize":
		v = &ClientPairFinalize{}
	case "server/pair-finalize":
		v = &ServerPairFinalize{}
	case "pair/abort":
		v = &PairAbort{}
	default:
		return UnknownMessage{Type: env.Type, Payload: env.Payload}, nil
	}
	if err := json.Unmarshal(env.Payload, v); err != nil {
		return nil, fmt.Errorf("malformed %s payload: %w", env.Type, err)
	}
	return v, nil
}
