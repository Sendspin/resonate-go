// ABOUTME: Tests for controller command messages — registry round-trips and
// ABOUTME: per-command parameter validation.
package session

import "testing"

func TestCommandMessages_RoundTrip(t *testing.T) {
	vol := 50
	mute := true
	for _, want := range []any{
		&ClientCommand{Controller: &ControllerCommand{Command: CmdVolume, Volume: &vol}},
		&ClientCommand{Controller: &ControllerCommand{Command: CmdSwitch, GroupID: "g1"}},
		&ServerCommand{Player: &PlayerCommand{Command: PlayerCmdMute, Mute: &mute}},
	} {
		raw, err := Marshal(want)
		if err != nil {
			t.Fatalf("marshal %T: %v", want, err)
		}
		got, err := Parse(raw)
		if err != nil {
			t.Fatalf("parse %T: %v", want, err)
		}
		if _, ok := got.(UnknownMessage); ok {
			t.Fatalf("%T parsed as UnknownMessage — not registered", want)
		}
	}
}

func TestControllerCommand_Validate(t *testing.T) {
	vol := 50
	bad := 150
	mute := true
	pos := 1000
	off := -500
	cases := []struct {
		name string
		cmd  ControllerCommand
		ok   bool
	}{
		{"play", ControllerCommand{Command: CmdPlay}, true},
		{"volume ok", ControllerCommand{Command: CmdVolume, Volume: &vol}, true},
		{"volume missing", ControllerCommand{Command: CmdVolume}, false},
		{"volume out of range", ControllerCommand{Command: CmdVolume, Volume: &bad}, false},
		{"mute ok", ControllerCommand{Command: CmdMute, Mute: &mute}, true},
		{"mute missing", ControllerCommand{Command: CmdMute}, false},
		{"seek ok", ControllerCommand{Command: CmdSeek, PositionMs: &pos}, true},
		{"seek missing", ControllerCommand{Command: CmdSeek}, false},
		{"seek_relative ok", ControllerCommand{Command: CmdSeekRelative, OffsetMs: &off}, true},
		{"seek_relative missing", ControllerCommand{Command: CmdSeekRelative}, false},
		{"switch ok", ControllerCommand{Command: CmdSwitch, GroupID: "g1"}, true},
		{"switch no group ok", ControllerCommand{Command: CmdSwitch}, true},
		{"stray volume on play", ControllerCommand{Command: CmdPlay, Volume: &vol}, false},
		{"stray position on pause", ControllerCommand{Command: CmdPause, PositionMs: &pos}, false},
		{"unknown command", ControllerCommand{Command: "frobnicate"}, false},
	}
	for _, c := range cases {
		err := c.cmd.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected an error", c.name)
		}
	}
}
