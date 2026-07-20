# Proposal: Go server compliance with the updated Sendspin spec

**Status:** Proposed
**Owner:** Chris
**Created:** 2026-07-18
**Spec:** [`Sendspin/spec`](https://github.com/Sendspin/spec) @ `7c04eb7` ("Keep the connection open across pairing attempts")

## Summary

The spec moved from `Sendspin/website/src/spec.md` to its own repo and has been
substantially revised. The changes fall into three tiers for the Go server
(`pkg/sendspin` + `pkg/protocol` in the SDK; the `sendspin-go-server` CLI is a
thin wrapper and mostly inherits compliance from the SDK):

1. **A new mandatory secure transport** — Noise-encrypted connections with a
   `client/init` → `server/init` → `noise/handshake`×2 preamble, identity =
   Curve25519 keypair, plus a full **pairing** subsystem (3 methods) and
   **management** commands. This replaces our plaintext
   `client/hello`-first handshake wholesale. Nothing of it exists today.
2. **Reworked core semantics** on the messages we already speak —
   `server/activate`, `available` boolean, new required player timing fields
   that change send-ahead scheduling, delta-merge rules, stream lifecycle
   prohibitions.
3. **New/expanded roles** the server must implement: `source@v1` (audio
   *input* clients), `color@v1`, and a concrete `visualizer@v1` wire format.

This is effectively **Sendspin protocol v2 in practice** (the spec keeps
`version: 1` but the handshake is incompatible with our current one). The
plan is a **hard cutover**: the new transport replaces the plaintext
handshake outright — no dual-support window. When the spec-v2
`sendspin-go-server` release ships, encryption is required; deployments that
need the old protocol stay on the v1.8.x / v0.1.x releases until both sides
upgrade (Music Assistant via an aiosendspin-7+ based provider).

## What is already compliant (verified against source)

| Area | Status |
|---|---|
| mDNS service types `_sendspin._tcp` / `_sendspin-server._tcp` + required `path` TXT | ✅ `pkg/discovery/mdns.go` |
| Server-initiated *and* client-initiated connections | ✅ (dialer + listener) |
| `client/time`/`server/time` echo with µs monotonic server clock | ✅ |
| Audio chunk binary layout: type `4`, 8-byte BE µs timestamp, payload | ✅ |
| Artwork binary types 8–11 (channels 0–3) | ✅ `CreateArtworkChunk` |
| Chunk duration inside the 15–150 ms bound | ✅ (20 ms) |
| Codecs opus/flac/pcm, per-client negotiation, `codec_header` (std Base64) | ✅ |
| PCM little-endian signed, 24-bit packed 3-byte | ✅ `pkg/audio` |
| `buffer_capacity` as hard byte cap on send-ahead | ✅ `buffer_tracker.go` |
| Late joiners get future timestamps only | ✅ |
| Metadata state: `timestamp`, tristate merge, `progress` w/ `playback_speed` | ✅ |
| `group/update` delta semantics incl. `group_name` field | ✅ |
| Controller `server/state`: `supported_commands`, repeat/shuffle | ✅ shape (commands limited, see gaps) |
| Volume→amplitude curve `(v/100)^1.5` (player side) | ✅ `pkg/audio/output` |
| Role versioning `role@vN`, first-match activation, `_`-prefix custom roles | ✅ `activateRoles` |

## Gap analysis

### Tier 1 — transport & trust (all-new, blocking for spec compliance)

| # | Gap | Spec section | Notes |
|---|-----|--------------|-------|
| 1.1 | `client/init`/`server/init` cleartext preamble; JSON-over-text only until transport mode, then **all frames binary** (JSON = binary type `0`) | Communication | Inverts our order — today the client speaks `client/hello` first and everything is text frames |
| 1.2 | Noise `KKpsk2`, server = initiator, suites `25519_ChaChaPoly_SHA256` **and** `25519_AESGCM_SHA256` (server must support both) | Encryption | New crypto core |
| 1.3 | Identity = Curve25519 static keypair; `server_id`/`client_id` = 43-char base64url pubkey, persisted | Identities | Replaces our UUID `server_id`; key must live in server config/state dir and be part of backup guidance |
| 1.4 | PSK machinery: `psk_id = SHA-256("sendspin-psk-id-v1"‖PSK)`, Sentinel PSK constant, per-pair long-term PSKs, prologue = exact `client/init`‖`server/init` bytes | Pre-Shared Key / Prologue | |
| 1.5 | In-band **re-handshake** (after pairing / key rotation) with prior hash `h` as prologue | Re-handshake | |
| 1.6 | **Fragmentation** types 2/3 for messages > 65 518 B | Fragmentation | Artwork images will exceed this routinely; server must fragment |
| 1.7 | **Pairing**: all 3 methods server-side — Pairing PSK, dynamic PIN (commit/reveal + PIN derivation), static PIN; CPACE-X25519-SHA512 w/ MCF; PSK wrapping; `pair/*` messages; `server/unpair`; unpaired-access policy; handshake-failure backoff | Pairing | Servers MUST implement all three. CPace has no mainstream Go library → implement per draft-irtf-cfrg-cpace (contained, testable against spec vectors) |
| 1.8 | **Management**: `management/list-records`, `add-record`, `remove-record`, `get/set-pairing-config`, `management/result` w/ storage accounting; `'management'` activity gating | Management | Server issues these; needed for any server UI over paired clients |
| 1.9 | `server/activate` message: `activities` (`playback`/`pairing`/`management`), `active_roles` **moved here** from `server/hello`; `server/hello` slims to `{name}`; nothing may flow before the first `server/activate` | server/activate | Our `connection_reason` field disappears |

### Tier 2 — core semantics on existing messages

| # | Gap | Notes |
|---|-----|-------|
| 2.1 | `client/state.state` string → **`available` boolean** (#115); solo-group/previous-group semantics on `available:false`; MUST NOT auto-rejoin on `available:true`; MUST NOT send `stream/start` or binary data to unavailable clients / before initial `client/state` | We key off `"synchronized"`/`"external_source"` strings today |
| 2.2 | New REQUIRED player state fields: `static_delay_ms`, `required_lead_time_ms`, `min_buffer_ms`, optional `supported_commands: ['set_static_delay']` — and the **send-ahead algorithm** built on them: first chunk ≥ `min_buffer_ms + static_delay_ms` lead, extend toward `required_lead_time_ms` for buffered (not live) sources, group send-ahead = max across members, recompute on membership/timing changes, rate-limit timing updates | Today we use a fixed ~500 ms `BufferAheadMs` + byte cap. This is the biggest *audio* behavior change |
| 2.3 | `client/state` **delta merge**: server must retain last value for absent fields (initial message = full state) | We overwrite volume/mute wholesale per message |
| 2.4 | `server/command` player `set_static_delay`; commands gated on the client's advertised `supported_commands` | We never send player commands today (controller volume path) |
| 2.5 | Stream lifecycle prohibitions: **no** stream messages on natural track transitions (gapless); `stream/clear` (never `stream/end`) for seeks *and track jumps*; `stream/start` re-sent on an active stream updates config without clearing | Audit `notifyStreamEnd` + engine transitions |
| 2.6 | `stream/request-format` with **no active stream**: don't start one; remember the format for the next stream (#112) | We respond only when streaming |
| 2.7 | Requested/started formats MUST be from the client's `supported_formats` list (strict) | Mostly true; enforce |
| 2.8 | Controller: `seek`/`seek_relative` (+`position_ms`/`offset_ms`, `seek_max_ms` in state, omit `seek` when unseekable), group-volume **delta redistribution algorithm** with clamp handling, group mute = all-muted, `switch` cycle w/ previous-group priority | Our `ControllerGroupRole` passes a bare command string; no params, no group-volume math |
| 2.9 | `client/goodbye` reasons expanded (`another_server`, `user_request`, `unauthorized`, `pairing_required`, `concurrent_attempt`, `unpaired`); no-goodbye drop ⇒ assume `restart` + auto-reconnect (for playback/empty activity sets) + backoff rules | We only special-case `restart` for re-dial |
| 2.10 | Forward compat: MUST ignore unknown fields (Go default ✅) but MUST NOT send undefined fields — our legacy MA-compat keys (`player_support`, `connection_reason`, unversioned support objects) are removed outright (no legacy path survives the cutover) | Delete, don't fence |
| 2.11 | `device_info.mac_address`, `trust_level`, `unpaired_access`, `supported_pair_methods` in `client/hello` — parse/store server-side | |

### Tier 3 — roles

| # | Gap | Notes |
|---|-----|-------|
| 3.1 | **`source@v1`** (#105): accept `client_stream/start`/`end`, binary type-12 timestamped input chunks, `server/command` source `start`/`stop` (default stop), feed captured audio into the engine as a source, tolerate timestamp discontinuities, **pairing required** (never over unpaired access) | Whole new input path into `internal/server`'s engine + a new `SourceGroupRole` |
| 3.2 | **`visualizer@v1`** concrete wire format: types 16–20 (`loudness`, `beat`, `f_peak`, `spectrum`, `peak`), uint16 A-weighted dB scaling, `rate_max`, spectrum binning (mel/log/lin), `tracks_downbeats` | Server streams none today. `loudness`/`spectrum`/`f_peak`/`peak` are cheap DSP; `beat` may be omitted from the echoed `types` (spec allows) |
| 3.3 | **`color@v1`**: `server/state` color object (palette w/ WCAG 4.5:1 contrast guarantees), timestamped | Derivable from artwork; contrast adjustment needed |
| 3.4 | Role omission escape hatch: server MAY decline to activate a role (`active_roles` note) — lets 3.2/3.3 ship after Tier 1/2 without blocking compliance claims per-connection | Use deliberately, not as a permanent dodge |

## Proposed plan

Ordering principle: transport first (everything else rides on it), semantics
second (independently testable), roles last. Each phase keeps
`make test` green; conformance runs against the updated harness once
`Sendspin/conformance` tracks the new spec (verify before starting — see Open
questions).

- **Phase S1 — Noise transport + new handshake (pkg/protocol).**
  `Identity` type (keygen/persist/base64url), `client/init`–`server/init`–
  `noise/handshake` state machine (server = initiator), both cipher suites,
  Sentinel PSK + `psk_id` selection, prologue binding, transport-mode
  binary framing (JSON = type 0), fragmentation (types 2/3), re-handshake,
  handshake timeouts + close-without-error policy. Library: `flynn/noise`
  (supports X25519/ChaChaPoly/AESGCM/SHA-256 and psk modifiers) +
  `x/crypto`. The new handshake **replaces** the legacy one — a first frame
  that isn't `client/init` closes the connection. No compatibility shim.
- **Phase S2 — session model (pkg/sendspin).** `server/activate` with
  `activities`/`active_roles`, slimmed `server/hello`, message-ordering
  enforcement, expanded goodbye reasons + reconnect/backoff policy,
  `trust_level`/`unpaired_access` plumbing, per-connection trust state.
- **Phase S3 — pairing + management.** Pairing record store (server side),
  Pairing-PSK flow, CPace implementation + vectors, dynamic-PIN
  (commit/reveal, PIN derive, operator entry API for the TUI/CLI), static-PIN,
  PSK wrapping, post-pairing re-handshake, `server/unpair`, management
  request/reply plumbing + storage accounting consumption. CLI surface in
  `sendspin-go-server`: operator commands to enter pairing, type PINs, list
  records.
- **Phase S4 — player semantics & scheduling.** `available` boolean +
  solo/previous-group moves, `client/state` delta merge, new timing fields →
  per-client/group send-ahead computation replacing fixed `BufferAheadMs`,
  `set_static_delay` command, stream lifecycle audit (gapless/clear-vs-end),
  request-format-with-no-stream memory, strict format-list enforcement.
- **Phase S5 — controller completion.** Command params (`volume`, `mute`,
  `position_ms`, `offset_ms`), group-volume redistribution algorithm, group
  mute, `seek_max_ms` maintenance, `switch` cycle with previous-group
  priority.
- **Phase S6 — new roles.** `source@v1` end-to-end (input chunks → engine →
  distribution), then `visualizer@v1` periodic types (`loudness`, `spectrum`,
  `f_peak`, `peak`; omit `beat` initially), then `color@v1` from artwork
  palette extraction. Until each lands, decline activation of that role
  (Tier 3.4).
- **Phase S7 — release cutover.** Conformance green on the new harness;
  coordinate the release with the aiosendspin-7+ Music Assistant provider;
  ship as a major SDK + server release that **requires** encryption.
  Release notes state plainly: old clients need the new release's
  counterpart; mixed old/new setups are not supported — pin v1.8.x/v0.1.x
  on both sides until ready to move together.

Client-side work (Receiver/Player in the SDK, `sendspin-go-cli`) mirrors S1,
S2, S4 and the client half of pairing — tracked separately, but S1's
transport code is shared by both sides, which is another argument for it
living in `pkg/protocol`.

## Effort & risk notes

- **Crypto surface** is the dominant risk: Noise integration is
  well-supported (`flynn/noise`), but CPace must be implemented from the
  draft. Mitigations: test vectors from the draft + cross-testing against
  `aiosendspin`'s implementation; keep all crypto in a new `pkg/protocol`
  sub-package with fuzz tests; the failure policy (close without
  application-level errors) is simple to honor.
- **Send-ahead rework (S4)** touches the interop-critical audio path —
  gate on the conformance suite and A/B against v1.8.x behavior with the
  existing hardware test setup (the 2×Pi + MA rig from #144 is ideal).
- The **`state`→`available` rename** and handshake inversion are hard
  breaks by design (no dual-support window). The protection for existing
  deployments is purely release-versioning: v1.8.x/v0.1.x remain available
  and untouched; the cutover release is opt-in by upgrading.
- `server_id` becomes the pubkey: persisted key material now determines
  server identity — document backup/restore in the server README
  (spec: Identities/Key rotation).

## Constraints & answers (from Chris, 2026-07-18)

1. **Conformance is not yet updated to the new spec** → this work stays
   **unreleased** until it is. Consequence: develop on a long-lived
   `feat/spec-v2` branch in the SDK (rebased regularly on `main`); no SDK
   tag containing the new path ships before the harness can gate it. The
   legacy path stays the only released behavior in the meantime.
2. **Interop peers for the encrypted path exist**: `aiosendspin` 7+
   implements the encryption (Noise/pairing) but **not** the `source`
   role; the (unreleased) **sendspindotnet** SDK also has encryption
   support. Plan impact: S1–S3 can be validated against aiosendspin 7+
   (and cross-checked against sendspindotnet) before conformance lands —
   real interop replaces the harness as the interim gate.
3. **`source@v1` has no reference peer anywhere yet** → it stays last in
   S6 and its activation stays declined until there is something to test
   against; this also derisks the engine-input work.

## Server-repo cutover (decided 2026-07-18, Chris)

The `sendspin-go-server` binary cuts **straight over** to the spec-v2
encrypted transport when the integration lands — no side-by-side / dual-mode
build in the server repo. The legacy server is replaced in place; users who
need a legacy peer stay on the current `v0.1.x` release line.

- The server repo's README carries a forward-looking **Compatibility** note
  stating the upcoming version will not interoperate with legacy
  pre-encryption implementations (added ahead of the cutover so it's already
  in the docs when the release ships).
- The current `v0.1.x` release stays accurate: it *is* the legacy-compatible
  server, so the note is framed as "the upcoming version," not a claim about
  what ships today. It converts to present-tense at the cutover release.
- Same principle applies to the SDK's own `pkg/sendspin` server API when it
  is rebuilt on the new transport (hard cutover, in place — see 2.10).

## Remaining open questions

1. Where does the server persist identity + pairing records?
   Proposal: `~/.config/sendspin/server-identity` + `server-pairings.yaml`
   (0600), configurable via the existing config-file machinery.
2. ~~Dual-support window~~ — resolved: none. The spec-v2 release requires
   encryption; coordination with MA happens at release time, not via a
   compatibility shim.
