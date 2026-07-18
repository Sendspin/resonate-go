// ABOUTME: The server/activate admissibility rules — the spec's PSK-category
// ABOUTME: activity table and the client-side verdict logic, as pure functions.
package session

import "fmt"

// PSKCategory classifies the PSK that matched during the Noise handshake.
type PSKCategory int

const (
	// PSKSentinel is the published constant used before any pairing exists.
	PSKSentinel PSKCategory = iota
	// PSKPairing is a Sendspin Pairing PSK (bootstrap secret for pairing).
	PSKPairing
	// PSKLongTerm is a long-term Sendspin PSK from a pairing record.
	PSKLongTerm
)

func (c PSKCategory) String() string {
	switch c {
	case PSKSentinel:
		return "sentinel"
	case PSKPairing:
		return "pairing"
	case PSKLongTerm:
		return "long-term"
	default:
		return fmt.Sprintf("psk-category(%d)", int(c))
	}
}

// ValidateActivities checks structural rules: members are spec-defined,
// unique, and unordered (order is irrelevant, duplicates are not allowed).
func ValidateActivities(activities []Activity) error {
	seen := map[Activity]bool{}
	for _, a := range activities {
		if !a.Valid() {
			return fmt.Errorf("unknown activity %q", string(a))
		}
		if seen[a] {
			return fmt.Errorf("duplicate activity %q", string(a))
		}
		seen[a] = true
	}
	return nil
}

// AllowedActivities reports whether the activity set is one the matched PSK
// category permits, per the spec's table:
//
//	Sendspin PSK (long-term): ['pairing'] or any subset of {'playback','management'}
//	Pairing PSK:              ['pairing']
//	Sentinel PSK:             [], ['pairing'], ['playback'] (the latter only
//	                          when the client has unpaired access enabled)
func AllowedActivities(psk PSKCategory, activities []Activity, unpairedAccessEnabled bool) bool {
	if ValidateActivities(activities) != nil {
		return false
	}
	has := map[Activity]bool{}
	for _, a := range activities {
		has[a] = true
	}
	pairing := has[ActivityPairing]

	switch psk {
	case PSKLongTerm:
		if pairing {
			return len(activities) == 1
		}
		return true // any subset of {playback, management}, including empty
	case PSKPairing:
		return pairing && len(activities) == 1
	case PSKSentinel:
		switch {
		case len(activities) == 0:
			return true
		case len(activities) == 1 && pairing:
			return true
		case len(activities) == 1 && has[ActivityPlayback]:
			return unpairedAccessEnabled
		default:
			return false
		}
	default:
		return false
	}
}

// PlaybackCapable reports whether the connection may carry non-empty
// active_roles: its activities extended with 'playback' must be an allowed
// set for the matched PSK.
func PlaybackCapable(psk PSKCategory, activities []Activity, unpairedAccessEnabled bool) bool {
	has := false
	for _, a := range activities {
		if a == ActivityPlayback {
			has = true
			break
		}
	}
	extended := activities
	if !has {
		extended = append(append([]Activity{}, activities...), ActivityPlayback)
	}
	return AllowedActivities(psk, extended, unpairedAccessEnabled)
}

// ClientAdmissionState is what the client knows when judging an activate.
type ClientAdmissionState struct {
	UnpairedAccessEnabled bool
	// OfferedPairMethods are the method names from the client's
	// supported_pair_methods in client/hello.
	OfferedPairMethods []string
	// ActiveRolesInEffect is the persisted active_roles from earlier
	// activates, applied when the new activate omits the field.
	ActiveRolesInEffect []string
}

// PairAbortReason enumerates pair/abort reasons this layer can produce.
type PairAbortReason string

// PairAbortMethodNotSupported is sent when the selected pair method is not a
// permitted or offered combination.
const PairAbortMethodNotSupported PairAbortReason = "method_not_supported"

// Verdict is the client-side decision on a server/activate.
type Verdict struct {
	// OK means the activate is admissible and the session continues.
	OK bool
	// Goodbye, when non-empty, is the client/goodbye reason to send before
	// closing.
	Goodbye GoodbyeReason
	// PairAbort, when non-empty, is the pair/abort reason to send before
	// closing.
	PairAbort PairAbortReason
}

// JudgeActivate applies the spec's client-side admissibility rules in order:
//
//  1. Sentinel PSK, unpaired access disabled, and enabling it would make the
//     activation admissible → goodbye 'pairing_required'.
//  2. Activities not allowed for the PSK, or non-empty active_roles on a
//     connection that is not playback-capable → goodbye 'unauthorized'.
//  3. 'pairing' declared with a selected_pair_method the PSK disallows or the
//     client did not offer → pair/abort method_not_supported.
func JudgeActivate(psk PSKCategory, act ServerActivate, state ClientAdmissionState) Verdict {
	if ValidateActivities(act.Activities) != nil {
		return Verdict{Goodbye: GoodbyeUnauthorized}
	}

	activeRoles := state.ActiveRolesInEffect
	if act.ActiveRoles != nil {
		activeRoles = *act.ActiveRoles
	}

	allowed := AllowedActivities(psk, act.Activities, state.UnpairedAccessEnabled)
	rolesOK := len(activeRoles) == 0 || PlaybackCapable(psk, act.Activities, state.UnpairedAccessEnabled)

	if !allowed || !rolesOK {
		// Rule 1: would enabling unpaired access fix it?
		if psk == PSKSentinel && !state.UnpairedAccessEnabled {
			wouldAllow := AllowedActivities(psk, act.Activities, true)
			wouldRolesOK := len(activeRoles) == 0 || PlaybackCapable(psk, act.Activities, true)
			if wouldAllow && wouldRolesOK {
				return Verdict{Goodbye: GoodbyePairingRequired}
			}
		}
		// Rule 2.
		return Verdict{Goodbye: GoodbyeUnauthorized}
	}

	// Rule 3: pairing-method consistency.
	pairing := false
	for _, a := range act.Activities {
		if a == ActivityPairing {
			pairing = true
		}
	}
	if pairing {
		m := act.SelectedPairMethod
		if m == "" {
			return Verdict{PairAbort: PairAbortMethodNotSupported}
		}
		// selected_pair_method must be 'pairing_psk' iff the PSK is the
		// Pairing PSK.
		if (m == "pairing_psk") != (psk == PSKPairing) {
			return Verdict{PairAbort: PairAbortMethodNotSupported}
		}
		offered := false
		for _, o := range state.OfferedPairMethods {
			if o == m {
				offered = true
			}
		}
		if !offered {
			return Verdict{PairAbort: PairAbortMethodNotSupported}
		}
	} else if act.SelectedPairMethod != "" {
		// selected_pair_method is "absent otherwise".
		return Verdict{Goodbye: GoodbyeUnauthorized}
	}

	return Verdict{OK: true}
}
