# §21 — PASE → SessionManager Handoff

**Date:** 2026-05-13
**Scope:** Close the last gap in [TODO.md §21](../../../TODO.md): wire the
PASE-derived `Ke` through to a real `*session.Session` installed in
`SessionManager`, so post-PASE traffic can run on the PASE-secure session
instead of unsecured session 0.

## Background

PASE currently completes (both peers reach `StateComplete` with matching
16-byte `Ke`), but neither side installs the resulting keys into
`SessionManager`. `crypto.DeriveSessionKeysFromKe` exists and is tested;
`SessionManager.InstallSecureSession(id, local, peer, keys, role)` exists
since §12. The missing piece is the connection between them.

## Goals

1. After successful PASE, both peers have a `*session.Session` registered
   in their respective `SessionManager`, keyed by each peer's own chosen
   `SessionID`, with the encrypt/decrypt keys correctly resolved for the
   peer's role.
2. The `commissioning` package is the single source of truth for *where*
   in the PASE state machine the install happens — callers (samples,
   tests, future orchestrators) cannot forget to do it.
3. Adequate test coverage for both correctness (key identity / mirroring)
   and end-to-end functionality (cross-peer AES-CCM round-trip).

## Non-goals

- Transport pass-through flip (TODO §17/18, separate work item).
- Group sessions (deferred per §12-15).
- CASE handshake (Phase 7).
- Real post-PASE protocol traffic — those are Interaction Model `Invoke`
  calls (Phase 9), not bespoke commissioning opcodes.
- Session lifecycle / eviction (§16).
- Public accessors on `Commissioner`/`Commissionee` for the installed
  session or raw `SessionKeys`. Tests reach for the `SessionManager`
  directly via `sm.Session(id)`. If a real consumer needs more, an
  accessor can be added later.

## Design Decisions

### D1 — `commissioning/` imports `session/`

The handoff happens inside `Commissioner.handlePake2` and
`Commissionee.handlePake3`, not in sample/orchestrator code. Rationale:

- Architectural stack (CLAUDE.md): `samples → commissioning → session →
  crypto`. `commissioning/ → session/` is downward flow and consistent
  with `commissioning/`'s existing imports of `crypto/` and `message/`.
- PASE *is* by definition "Password Authenticated Session Establishment"
  (Matter §4.13). An API that reaches `StateComplete` without installing
  a session models PASE incompletely.
- CASE (§27) will need the identical pattern — putting the install in
  the protocol layer avoids duplicating "the caller must remember" at
  both PASE and CASE call sites.

### D2 — Required constructor argument

Both `NewCommissioner` and `NewCommissionee` take `*session.SessionManager`
as a required argument. `NewCommissionee` already returns `error` and
fails fast on nil; `NewCommissioner` documents nil as a programmer error
(it would nil-deref on first install attempt — Go-idiomatic for required
dependencies). Future improvement (out of scope): switch to a DI container
like `wire` once the dependency graph grows.

### D3 — NodeIDs are zero, named via `session.UnspecifiedNodeID`

Verified against the reference implementation:

- [`connectedhomeip/src/transport/SecureSessionTable.cpp:40-52`](https://github.com/project-chip/connectedhomeip/blob/master/src/transport/SecureSessionTable.cpp)
  explicitly rejects PASE sessions with any value other than
  `kUndefinedNodeId` / `kUndefinedFabricIndex`.
- [`connectedhomeip/src/lib/core/NodeId.h:31`](https://github.com/project-chip/connectedhomeip/blob/master/src/lib/core/NodeId.h#L31):
  `kUndefinedNodeId = 0ULL`.
- [`connectedhomeip/src/transport/SessionManager.cpp:286-289`](https://github.com/project-chip/connectedhomeip/blob/master/src/transport/SessionManager.cpp)
  shows this zero value flows into `BuildNonce` for the secure-session
  send path.

We introduce a named constant `session.UnspecifiedNodeID = 0` so the
intent is visible at both call sites (rather than naked `0` literals).

### D4 — Install timing: derive → install → state → send

In `handlePake2` (Commissioner):

1. `keys, err := crypto.DeriveSessionKeysFromKe(c.Ke)` — error bubbles up,
   no state transition, no Pake3 sent.
2. `sm.InstallSecureSession(c.SessionID, UnspecifiedNodeID, UnspecifiedNodeID, keys, RoleInitiator)`.
3. Build Pake3 frame.
4. `c.State = StateComplete`.
5. Send Pake3.

In `handlePake3` (Commissionee): identical except role is `RoleResponder`
and no outbound frame follows. Rationale: install before the state flip
means an observer who sees `StateComplete` can rely on the session being
present in the manager.

### D5 — Test coverage: key mirroring + cross-encrypt round-trip

Two new tests added to `commissioning/commissioning_test.go`:

- **`TestPASE_InstallsSecureSession`** — asserts both managers hold a
  session under each peer's `SessionID`, that the encrypt/decrypt keys
  are mirrored across peers (Commissioner's `EncryptKey` equals
  Commissionee's `DecryptKey`, and vice versa), that the
  `AttestationChallenge` matches, and that local/peer NodeIDs are zero.
- **`TestPASE_CrossEncryptRoundtrip`** — after PASE, encrypts a plaintext
  on one peer's manager and decrypts it on the other. Run in both
  directions. This is the test that would catch a swapped-role bug,
  which is the most likely mistake in role-conditional key selection.

The existing `pasePair` helper grows to construct and return both
`*session.SessionManager` instances so tests can inspect them.

## API Changes

### `session/session.go`

```go
const UnspecifiedNodeID uint64 = 0
```

One short doc comment citing the reference-impl behavior; the constant
earns its keep by replacing magic-number `0` literals at the call sites.

### `commissioning/commissioner.go`

```go
func NewCommissioner(messenger CommissioningMessenger, sm *session.SessionManager) *Commissioner
```

New field `SessionManager *session.SessionManager`. `handlePake2` does
the derive+install per D4.

### `commissioning/commissionee.go`

```go
func NewCommissionee(passcode uint32, salt []byte, iterations int, sm *session.SessionManager) (*Commissionee, error)
```

Returns error on `sm == nil`. New field `SessionManager
*session.SessionManager`. `handlePake3` does the derive+install per D4.

### Samples

[`samples/commissioning/controller/main.go`](../../../samples/commissioning/controller/main.go)
and [`samples/commissioning/device/main.go`](../../../samples/commissioning/device/main.go):

- Construct a `*session.SessionManager` with `nil` `PayloadHandler` (the
  samples don't drive a decrypt loop yet).
- Pass it to the respective constructor.
- After `StateComplete`, log one extra line confirming the install
  (session ID + an `AttestationChallenge` prefix). No new wire traffic.

## File Touch List

```
session/session.go                        (new constant)
commissioning/commissioner.go             (constructor signature + handlePake2)
commissioning/commissionee.go             (constructor signature + handlePake3)
commissioning/commissioning_test.go       (pasePair helper, new tests, existing test signatures)
samples/commissioning/controller/main.go  (sm construction + constructor call + log)
samples/commissioning/device/main.go      (sm construction + constructor call + log)
TODO.md                                   (mark §21 complete, update snapshot)
```

## Verification

- `go build ./...` clean.
- `go test ./...` clean — including the two new tests.
- Both samples still build and run end-to-end over loopback; new log line
  visible on both sides after Pake3.
