// ABOUTME: Controller command messages — client/command (controller verbs) and
// ABOUTME: server/command (per-player volume/mute/static-delay directives).
package session

import "fmt"

// MediaCommand is a controller command verb carried in client/command.
type MediaCommand string

const (
	CmdPlay         MediaCommand = "play"
	CmdPause        MediaCommand = "pause"
	CmdStop         MediaCommand = "stop"
	CmdNext         MediaCommand = "next"
	CmdPrevious     MediaCommand = "previous"
	CmdVolume       MediaCommand = "volume"
	CmdMute         MediaCommand = "mute"
	CmdRepeatOff    MediaCommand = "repeat_off"
	CmdRepeatOne    MediaCommand = "repeat_one"
	CmdRepeatAll    MediaCommand = "repeat_all"
	CmdShuffle      MediaCommand = "shuffle"
	CmdUnshuffle    MediaCommand = "unshuffle"
	CmdSwitch       MediaCommand = "switch"
	CmdSeek         MediaCommand = "seek"
	CmdSeekRelative MediaCommand = "seek_relative"
)

// Valid reports whether c is a spec-defined controller command.
func (c MediaCommand) Valid() bool {
	switch c {
	case CmdPlay, CmdPause, CmdStop, CmdNext, CmdPrevious, CmdVolume, CmdMute,
		CmdRepeatOff, CmdRepeatOne, CmdRepeatAll, CmdShuffle, CmdUnshuffle,
		CmdSwitch, CmdSeek, CmdSeekRelative:
		return true
	}
	return false
}

// ControllerCommand is the controller object of client/command. Only the field
// matching the command is set (volume for volume, mute for mute, position_ms
// for seek, offset_ms for seek_relative, group_id for switch).
type ControllerCommand struct {
	Command    MediaCommand `json:"command"`
	Volume     *int         `json:"volume,omitempty"`
	Mute       *bool        `json:"mute,omitempty"`
	PositionMs *int         `json:"position_ms,omitempty"`
	OffsetMs   *int         `json:"offset_ms,omitempty"`
	GroupID    string       `json:"group_id,omitempty"`
}

// Validate checks the command verb and that exactly the command's own
// parameter is present, mirroring the spec's per-command field rules.
func (c ControllerCommand) Validate() error {
	if !c.Command.Valid() {
		return fmt.Errorf("unknown controller command %q", string(c.Command))
	}
	switch c.Command {
	case CmdVolume:
		if c.Volume == nil {
			return fmt.Errorf("volume command requires volume")
		}
		if *c.Volume < 0 || *c.Volume > 100 {
			return fmt.Errorf("volume %d out of range 0-100", *c.Volume)
		}
	case CmdMute:
		if c.Mute == nil {
			return fmt.Errorf("mute command requires mute")
		}
	case CmdSeek:
		if c.PositionMs == nil {
			return fmt.Errorf("seek command requires position_ms")
		}
		if *c.PositionMs < 0 {
			return fmt.Errorf("position_ms %d must be non-negative", *c.PositionMs)
		}
	case CmdSeekRelative:
		if c.OffsetMs == nil {
			return fmt.Errorf("seek_relative command requires offset_ms")
		}
	case CmdSwitch:
		// group_id is optional: an empty group_id means cycle/new solo group.
	}
	// Reject parameters that do not belong to the command.
	if c.Volume != nil && c.Command != CmdVolume {
		return fmt.Errorf("volume must not be set for %q", string(c.Command))
	}
	if c.Mute != nil && c.Command != CmdMute {
		return fmt.Errorf("mute must not be set for %q", string(c.Command))
	}
	if c.PositionMs != nil && c.Command != CmdSeek {
		return fmt.Errorf("position_ms must not be set for %q", string(c.Command))
	}
	if c.OffsetMs != nil && c.Command != CmdSeekRelative {
		return fmt.Errorf("offset_ms must not be set for %q", string(c.Command))
	}
	return nil
}

// ClientCommand is the client→server client/command message. The controller
// object is present when the sender holds the controller role.
type ClientCommand struct {
	Controller *ControllerCommand `json:"controller,omitempty"`
}

// PlayerCmd is a server→player command verb carried in server/command.
type PlayerCmd string

const (
	PlayerCmdVolume         PlayerCmd = "volume"
	PlayerCmdMute           PlayerCmd = "mute"
	PlayerCmdSetStaticDelay PlayerCmd = "set_static_delay"
)

// Valid reports whether c is a spec-defined player command.
func (c PlayerCmd) Valid() bool {
	return c == PlayerCmdVolume || c == PlayerCmdMute || c == PlayerCmdSetStaticDelay
}

// PlayerCommand is the player object of server/command: a directive to one
// player to change its volume, mute, or static delay.
type PlayerCommand struct {
	Command       PlayerCmd `json:"command"`
	Volume        *int      `json:"volume,omitempty"`
	Mute          *bool     `json:"mute,omitempty"`
	StaticDelayMs *int      `json:"static_delay_ms,omitempty"`
}

// ServerCommand is the server→client server/command message.
type ServerCommand struct {
	Player *PlayerCommand `json:"player,omitempty"`
}
