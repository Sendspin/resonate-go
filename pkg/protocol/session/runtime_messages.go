// ABOUTME: Runtime playback control messages — client/state, group/update, and
// ABOUTME: the stream lifecycle (stream/start, stream/end) exchanged post-setup.
package session

// PlaybackState is a group's binary playback state.
type PlaybackState string

const (
	// PlaybackPlaying means the group is streaming audio.
	PlaybackPlaying PlaybackState = "playing"
	// PlaybackStopped means the group is idle.
	PlaybackStopped PlaybackState = "stopped"
)

// Valid reports whether p is a spec-defined playback state.
func (p PlaybackState) Valid() bool { return p == PlaybackPlaying || p == PlaybackStopped }

// ClientState is the client→server client/state message: availability plus an
// optional player sub-object. Every field is a pointer so a delta update
// (carrying only the changed fields, which the server merges into existing
// state) is distinguishable from an initial full state where all are present.
type ClientState struct {
	Available *bool              `json:"available,omitempty"`
	Player    *ClientPlayerState `json:"player,omitempty"`
}

// ClientPlayerState is the player object of client/state: the timing fields the
// server's send-ahead scheduler consumes plus volume/mute and the optional
// supported-command list. Pointers mark absent (unchanged) fields in a delta.
type ClientPlayerState struct {
	StaticDelayMs      *int     `json:"static_delay_ms,omitempty"`
	RequiredLeadTimeMs *int     `json:"required_lead_time_ms,omitempty"`
	MinBufferMs        *int     `json:"min_buffer_ms,omitempty"`
	BufferCapacity     *int     `json:"buffer_capacity,omitempty"`
	Volume             *int     `json:"volume,omitempty"`
	Mute               *bool    `json:"mute,omitempty"`
	SupportedCommands  []string `json:"supported_commands,omitempty"`
}

// GroupUpdate is the server→client group/update message. It carries delta
// updates — only the changed fields are present — that the client merges into
// its group state.
type GroupUpdate struct {
	PlaybackState PlaybackState `json:"playback_state,omitempty"`
	GroupID       string        `json:"group_id,omitempty"`
	GroupName     string        `json:"group_name,omitempty"`
}

// StreamStartPlayer is the negotiated player audio format carried in
// stream/start.
type StreamStartPlayer struct {
	Codec      string `json:"codec"`
	Channels   int    `json:"channels"`
	SampleRate int    `json:"sample_rate"`
	BitDepth   int    `json:"bit_depth"`
}

// StreamStart is the server→client stream/start message opening a stream.
// ServerTransmitted is the server-clock microsecond timestamp stamped at send.
type StreamStart struct {
	ServerTransmitted int64              `json:"server_transmitted"`
	Player            *StreamStartPlayer `json:"player,omitempty"`
}

// StreamEnd is the server→client stream/end message closing active streams.
// ServerTransmitted is the server-clock microsecond timestamp stamped at send;
// Roles, when present, restricts the end to those role families (all if
// omitted).
type StreamEnd struct {
	ServerTransmitted int64    `json:"server_transmitted"`
	Roles             []string `json:"roles,omitempty"`
}
