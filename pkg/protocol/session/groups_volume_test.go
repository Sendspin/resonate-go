// ABOUTME: Tests for group volume/mute — the redistribution algorithm and the
// ABOUTME: per-member server/command directives it emits.
package session

import (
	"testing"

	"github.com/Sendspin/sendspin-go/pkg/protocol/playback"
	"github.com/Sendspin/sendspin-go/pkg/protocol/secure"
)

func mustServerCommand(t *testing.T, c *secure.Conn) *PlayerCommand {
	t.Helper()
	msg := readMsg(t, c)
	sc, ok := msg.(*ServerCommand)
	if !ok || sc.Player == nil {
		t.Fatalf("got %#v, want *ServerCommand with player", msg)
	}
	return sc.Player
}

// twoMemberGroup joins A and B, gathers B into A's group, and drains the
// group/update traffic so only later messages remain to read.
func twoMemberGroup(t *testing.T, m *GroupManager) (gid string, ccA, ccB *secure.Conn) {
	t.Helper()
	scA, ccA := connPair(t)
	scB, ccB := connPair(t)
	gid, _ = m.Join("A", scA, playback.Timing{}, 0)
	mustGroupUpdate(t, ccA)
	_, _ = m.Join("B", scB, playback.Timing{}, 0)
	mustGroupUpdate(t, ccB)
	if err := m.MoveToGroup("B", gid); err != nil {
		t.Fatal(err)
	}
	mustGroupUpdate(t, ccB) // move update
	return gid, ccA, ccB
}

func TestGroupManager_VolumeRedistribution(t *testing.T) {
	m := newTestManager()
	gid, _, ccB := twoMemberGroup(t, m)

	// A at 0, B at default 100 → group average 50.
	zero := 0
	if err := m.ApplyClientState("A", ClientState{Player: &ClientPlayerState{Volume: &zero}}); err != nil {
		t.Fatal(err)
	}
	if v := m.GroupVolume(gid); v != 50 {
		t.Fatalf("group volume = %d, want 50", v)
	}

	// Target 30: A is clamped at 0 (no headroom down), so B absorbs the whole
	// shortfall and lands at 60 → average exactly 30.
	if err := m.SetGroupVolume(gid, 30); err != nil {
		t.Fatal(err)
	}
	// Only B changed, so only B receives a server/command.
	pc := mustServerCommand(t, ccB)
	if pc.Command != PlayerCmdVolume || pc.Volume == nil || *pc.Volume != 60 {
		t.Fatalf("B server/command = %#v, want volume 60", pc)
	}
	if v := m.GroupVolume(gid); v != 30 {
		t.Errorf("group volume after set = %d, want 30", v)
	}
}

func TestGroupManager_VolumeUniformWhenHeadroom(t *testing.T) {
	m := newTestManager()
	gid, ccA, ccB := twoMemberGroup(t, m)

	// Both at default 100 → set to 40: uniform delta, both land at 40.
	if err := m.SetGroupVolume(gid, 40); err != nil {
		t.Fatal(err)
	}
	for _, cc := range []*secure.Conn{ccA, ccB} {
		if pc := mustServerCommand(t, cc); pc.Volume == nil || *pc.Volume != 40 {
			t.Errorf("server/command = %#v, want volume 40", pc)
		}
	}
	if v := m.GroupVolume(gid); v != 40 {
		t.Errorf("group volume = %d, want 40", v)
	}
}

func TestGroupManager_GroupMute(t *testing.T) {
	m := newTestManager()
	gid, ccA, ccB := twoMemberGroup(t, m)

	if m.GroupMuted(gid) {
		t.Fatal("group should start unmuted")
	}
	if err := m.SetGroupMute(gid, true); err != nil {
		t.Fatal(err)
	}
	for _, cc := range []*secure.Conn{ccA, ccB} {
		if pc := mustServerCommand(t, cc); pc.Command != PlayerCmdMute || pc.Mute == nil || !*pc.Mute {
			t.Errorf("server/command = %#v, want mute true", pc)
		}
	}
	if !m.GroupMuted(gid) {
		t.Error("group should be muted after SetGroupMute(true)")
	}

	// Idempotent: re-muting sends nothing (no member changed).
	if err := m.SetGroupMute(gid, true); err != nil {
		t.Fatal(err)
	}
	// Unmute both.
	if err := m.SetGroupMute(gid, false); err != nil {
		t.Fatal(err)
	}
	for _, cc := range []*secure.Conn{ccA, ccB} {
		if pc := mustServerCommand(t, cc); pc.Mute == nil || *pc.Mute {
			t.Errorf("server/command = %#v, want mute false", pc)
		}
	}
	if m.GroupMuted(gid) {
		t.Error("group should be unmuted")
	}
}

func TestGroupManager_MuteReflectsClientState(t *testing.T) {
	m := newTestManager()
	gid, _, _ := twoMemberGroup(t, m)

	// Group mute is true only when ALL members are muted.
	yes := true
	if err := m.ApplyClientState("A", ClientState{Player: &ClientPlayerState{Mute: &yes}}); err != nil {
		t.Fatal(err)
	}
	if m.GroupMuted(gid) {
		t.Error("group muted with only one member muted")
	}
	if err := m.ApplyClientState("B", ClientState{Player: &ClientPlayerState{Mute: &yes}}); err != nil {
		t.Fatal(err)
	}
	if !m.GroupMuted(gid) {
		t.Error("group not muted with all members muted")
	}
}
