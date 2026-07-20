// ABOUTME: Round-trip tests for the runtime playback control messages through
// ABOUTME: the shared Marshal/Parse registry.
package session

import "testing"

func TestRuntimeMessages_RoundTrip(t *testing.T) {
	avail := true
	vol := 80
	mute := false
	sd, lead, minb, cap := 10, 200, 150, 65536
	cases := []any{
		&ClientState{
			Available: &avail,
			Player: &ClientPlayerState{
				StaticDelayMs: &sd, RequiredLeadTimeMs: &lead, MinBufferMs: &minb,
				BufferCapacity: &cap, Volume: &vol, Mute: &mute,
				SupportedCommands: []string{"set_static_delay"},
			},
		},
		&GroupUpdate{PlaybackState: PlaybackPlaying, GroupID: "g1", GroupName: "Kitchen"},
		&StreamStart{ServerTransmitted: 123456, Player: &StreamStartPlayer{Codec: "opus", Channels: 2, SampleRate: 48000, BitDepth: 16}},
		&StreamEnd{ServerTransmitted: 789, Roles: []string{"player"}},
	}
	for _, want := range cases {
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

func TestClientState_DeltaOmitsAbsentFields(t *testing.T) {
	// A delta carrying only min_buffer_ms must not serialize the other fields.
	minb := 300
	raw, err := Marshal(&ClientState{Player: &ClientPlayerState{MinBufferMs: &minb}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := got.(*ClientState)
	if !ok {
		t.Fatalf("parsed %T, want *ClientState", got)
	}
	if st.Available != nil {
		t.Error("available present in a delta that omitted it")
	}
	if st.Player == nil || st.Player.MinBufferMs == nil || *st.Player.MinBufferMs != 300 {
		t.Errorf("min_buffer_ms not round-tripped: %+v", st.Player)
	}
	if st.Player.StaticDelayMs != nil || st.Player.Volume != nil {
		t.Error("absent player fields should be nil after a delta round-trip")
	}
}

func TestPlaybackState_Valid(t *testing.T) {
	if !PlaybackPlaying.Valid() || !PlaybackStopped.Valid() {
		t.Error("playing/stopped should be valid")
	}
	if PlaybackState("paused").Valid() {
		t.Error("paused is not a spec playback state")
	}
}
