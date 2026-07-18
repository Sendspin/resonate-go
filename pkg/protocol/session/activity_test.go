// ABOUTME: Table tests for the server/activate admissibility rules — every
// ABOUTME: row of the spec's PSK-category table plus the verdict ordering.
package session

import "testing"

func acts(a ...Activity) []Activity { return a }

func TestAllowedActivities_SpecTable(t *testing.T) {
	cases := []struct {
		name     string
		psk      PSKCategory
		acts     []Activity
		unpaired bool
		want     bool
	}{
		// Sendspin PSK (long-term): ['pairing'] or any subset of {playback, management}.
		{"longterm empty", PSKLongTerm, acts(), false, true},
		{"longterm playback", PSKLongTerm, acts(ActivityPlayback), false, true},
		{"longterm management", PSKLongTerm, acts(ActivityManagement), false, true},
		{"longterm playback+management", PSKLongTerm, acts(ActivityPlayback, ActivityManagement), false, true},
		{"longterm pairing", PSKLongTerm, acts(ActivityPairing), false, true},
		{"longterm pairing+playback", PSKLongTerm, acts(ActivityPairing, ActivityPlayback), false, false},
		// Pairing PSK: only ['pairing'].
		{"pairingpsk pairing", PSKPairing, acts(ActivityPairing), false, true},
		{"pairingpsk empty", PSKPairing, acts(), false, false},
		{"pairingpsk playback", PSKPairing, acts(ActivityPlayback), false, false},
		{"pairingpsk pairing+management", PSKPairing, acts(ActivityPairing, ActivityManagement), false, false},
		// Sentinel: [], ['pairing'], ['playback'] with unpaired access only.
		{"sentinel empty", PSKSentinel, acts(), false, true},
		{"sentinel pairing", PSKSentinel, acts(ActivityPairing), false, true},
		{"sentinel playback unpaired-on", PSKSentinel, acts(ActivityPlayback), true, true},
		{"sentinel playback unpaired-off", PSKSentinel, acts(ActivityPlayback), false, false},
		{"sentinel management", PSKSentinel, acts(ActivityManagement), true, false},
		{"sentinel playback+management", PSKSentinel, acts(ActivityPlayback, ActivityManagement), true, false},
		// Structural rules.
		{"duplicate activity", PSKLongTerm, acts(ActivityPlayback, ActivityPlayback), false, false},
		{"unknown activity", PSKLongTerm, []Activity{"streaming"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AllowedActivities(tc.psk, tc.acts, tc.unpaired); got != tc.want {
				t.Errorf("AllowedActivities(%v, %v, unpaired=%v) = %v, want %v",
					tc.psk, tc.acts, tc.unpaired, got, tc.want)
			}
		})
	}
}

func TestPlaybackCapable(t *testing.T) {
	// Long-term PSK with only management declared: extending with playback is
	// allowed, so the connection may carry roles even without 'playback'.
	if !PlaybackCapable(PSKLongTerm, acts(ActivityManagement), false) {
		t.Error("long-term management connection should be playback-capable")
	}
	// Pairing PSK is never playback-capable.
	if PlaybackCapable(PSKPairing, acts(ActivityPairing), false) {
		t.Error("pairing-psk connection must not be playback-capable")
	}
	// Sentinel without unpaired access is not playback-capable.
	if PlaybackCapable(PSKSentinel, acts(), false) {
		t.Error("sentinel connection without unpaired access must not be playback-capable")
	}
	if !PlaybackCapable(PSKSentinel, acts(), true) {
		t.Error("sentinel connection with unpaired access should be playback-capable")
	}
}

func roles(r ...string) *[]string { s := append([]string{}, r...); return &s }

func TestJudgeActivate_VerdictRules(t *testing.T) {
	cases := []struct {
		name    string
		psk     PSKCategory
		act     ServerActivate
		state   ClientAdmissionState
		wantOK  bool
		goodbye GoodbyeReason
		abort   PairAbortReason
	}{
		{
			name:   "unpaired playback admitted",
			psk:    PSKSentinel,
			act:    ServerActivate{Activities: acts(ActivityPlayback), ActiveRoles: roles("player@v1")},
			state:  ClientAdmissionState{UnpairedAccessEnabled: true},
			wantOK: true,
		},
		{
			// Rule 1 beats rule 2: enabling unpaired access would admit it.
			name:    "sentinel playback without unpaired access -> pairing_required",
			psk:     PSKSentinel,
			act:     ServerActivate{Activities: acts(ActivityPlayback), ActiveRoles: roles()},
			state:   ClientAdmissionState{UnpairedAccessEnabled: false},
			goodbye: GoodbyePairingRequired,
		},
		{
			// Rule 2: management on sentinel is never admissible.
			name:    "sentinel management -> unauthorized",
			psk:     PSKSentinel,
			act:     ServerActivate{Activities: acts(ActivityManagement), ActiveRoles: roles()},
			state:   ClientAdmissionState{UnpairedAccessEnabled: true},
			goodbye: GoodbyeUnauthorized,
		},
		{
			// Rule 2: roles on a non-playback-capable connection.
			name:    "roles on pairing-psk connection -> unauthorized",
			psk:     PSKPairing,
			act:     ServerActivate{Activities: acts(ActivityPairing), ActiveRoles: roles("player@v1"), SelectedPairMethod: "pairing_psk"},
			state:   ClientAdmissionState{OfferedPairMethods: []string{"pairing_psk"}},
			goodbye: GoodbyeUnauthorized,
		},
		{
			name:   "pairing-psk pairing with matching method",
			psk:    PSKPairing,
			act:    ServerActivate{Activities: acts(ActivityPairing), ActiveRoles: roles(), SelectedPairMethod: "pairing_psk"},
			state:  ClientAdmissionState{OfferedPairMethods: []string{"pairing_psk"}},
			wantOK: true,
		},
		{
			// Rule 3: pairing_psk method on a non-pairing PSK.
			name:  "sentinel pairing with pairing_psk method -> method_not_supported",
			psk:   PSKSentinel,
			act:   ServerActivate{Activities: acts(ActivityPairing), ActiveRoles: roles(), SelectedPairMethod: "pairing_psk"},
			state: ClientAdmissionState{OfferedPairMethods: []string{"pairing_psk", "static_pin"}},
			abort: PairAbortMethodNotSupported,
		},
		{
			// Rule 3: method the client did not offer.
			name:  "pairing with unoffered method -> method_not_supported",
			psk:   PSKSentinel,
			act:   ServerActivate{Activities: acts(ActivityPairing), ActiveRoles: roles(), SelectedPairMethod: "dynamic_pin"},
			state: ClientAdmissionState{OfferedPairMethods: []string{"static_pin"}},
			abort: PairAbortMethodNotSupported,
		},
		{
			// Rule 3: pairing without a selected method.
			name:  "pairing without selected method -> method_not_supported",
			psk:   PSKSentinel,
			act:   ServerActivate{Activities: acts(ActivityPairing), ActiveRoles: roles()},
			state: ClientAdmissionState{OfferedPairMethods: []string{"static_pin"}},
			abort: PairAbortMethodNotSupported,
		},
		{
			// selected_pair_method must be absent without 'pairing'.
			name:    "method without pairing activity -> unauthorized",
			psk:     PSKLongTerm,
			act:     ServerActivate{Activities: acts(ActivityPlayback), ActiveRoles: roles(), SelectedPairMethod: "static_pin"},
			state:   ClientAdmissionState{},
			goodbye: GoodbyeUnauthorized,
		},
		{
			// Omitted active_roles persists previous roles — still needs
			// playback capability.
			name:    "persisted roles on pairing psk -> unauthorized",
			psk:     PSKPairing,
			act:     ServerActivate{Activities: acts(ActivityPairing), SelectedPairMethod: "pairing_psk"},
			state:   ClientAdmissionState{OfferedPairMethods: []string{"pairing_psk"}, ActiveRolesInEffect: []string{"player@v1"}},
			goodbye: GoodbyeUnauthorized,
		},
		{
			name:   "longterm management-only with roles (playback-capable)",
			psk:    PSKLongTerm,
			act:    ServerActivate{Activities: acts(ActivityManagement), ActiveRoles: roles("player@v1")},
			state:  ClientAdmissionState{},
			wantOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := JudgeActivate(tc.psk, tc.act, tc.state)
			if v.OK != tc.wantOK || v.Goodbye != tc.goodbye || v.PairAbort != tc.abort {
				t.Errorf("JudgeActivate = %+v, want ok=%v goodbye=%q abort=%q",
					v, tc.wantOK, tc.goodbye, tc.abort)
			}
		})
	}
}
