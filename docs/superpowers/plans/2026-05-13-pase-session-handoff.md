# PASE → SessionManager Handoff — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After PASE completes, both peers install the derived session keys into their `*session.SessionManager`, bridging from unsecured session 0 to the PASE-secure session.

**Architecture:** `commissioning/` gains a downward dependency on `session/`. `Commissioner.handlePake2` and `Commissionee.handlePake3` each call `crypto.DeriveSessionKeysFromKe` followed by `SessionManager.InstallSecureSession` before flipping state to `StateComplete`. Both constructors require a non-nil `*session.SessionManager`. Node IDs are `session.UnspecifiedNodeID` (0) per the `connectedhomeip` reference impl.

**Tech Stack:** Go 1.25, existing `tlv`/`message`/`crypto`/`session`/`commissioning` packages. No new dependencies.

**Spec:** [docs/superpowers/specs/2026-05-13-pase-session-handoff-design.md](../specs/2026-05-13-pase-session-handoff-design.md)

---

## File Touch Map

| File | Action | Why |
|---|---|---|
| `session/session.go` | Modify | Add `UnspecifiedNodeID` constant |
| `commissioning/commissioner.go` | Modify | Constructor signature + new field + install in `handlePake2` |
| `commissioning/commissionee.go` | Modify | Constructor signature + new field + nil-check + install in `handlePake3` |
| `commissioning/commissioning_test.go` | Modify | `pasePair` helper signature, new install + cross-encrypt tests |
| `samples/commissioning/controller/main.go` | Modify | Construct SM, pass to constructor, log on completion |
| `samples/commissioning/device/main.go` | Modify | Same as controller |
| `TODO.md` | Modify | Mark §21 done, refresh snapshot |

---

## Task 1: Add `UnspecifiedNodeID` constant

**Files:**
- Modify: `session/session.go` (add constant near `UnsecuredSessionID`)

- [ ] **Step 1: Add the constant**

Open `session/session.go`. Find the existing `UnsecuredSessionID` declaration (around line 19). Add the new constant immediately after it:

```go
// UnspecifiedNodeID is the value used for both local and peer Node IDs
// when installing a PASE-secure session. PASE runs before fabric
// provisioning, so neither side has an operational Node ID yet; the
// reference implementation (connectedhomeip's SecureSessionTable.cpp)
// explicitly rejects any other value for kPASE sessions. The zero is
// also what flows into the AES-CCM nonce on the secure-session send
// path (connectedhomeip SessionManager.cpp:286-289).
const UnspecifiedNodeID uint64 = 0
```

- [ ] **Step 2: Verify build**

Run: `go build ./...`
Expected: clean build, no errors.

- [ ] **Step 3: Commit**

```bash
git add session/session.go
git commit -m "Add session.UnspecifiedNodeID for PASE NodeID slots"
```

---

## Task 2: Update constructor signatures (no behavior change yet)

**Files:**
- Modify: `commissioning/commissioner.go`
- Modify: `commissioning/commissionee.go`
- Modify: `commissioning/commissioning_test.go` (update `pasePair` + existing test call sites)
- Modify: `samples/commissioning/controller/main.go` (update constructor call)
- Modify: `samples/commissioning/device/main.go` (update constructor call)

This is a pure refactor: signatures change, a new field is stored, existing tests stay green. The install logic comes in Tasks 3 and 4.

- [ ] **Step 1: Update `Commissioner` struct and constructor**

In `commissioning/commissioner.go`:

Add to the imports block:
```go
"go-matter/session"
```

In the `Commissioner` struct, add a field after `Messenger`:
```go
SessionManager *session.SessionManager
```

Replace the `NewCommissioner` function:
```go
// NewCommissioner constructs a Commissioner. sm must not be nil — PASE
// produces a secure session which is installed in sm after Pake2; passing
// nil is a programmer error and will nil-deref on first install attempt.
func NewCommissioner(messenger CommissioningMessenger, sm *session.SessionManager) *Commissioner {
	return &Commissioner{State: StateIdle, Messenger: messenger, SessionManager: sm}
}
```

- [ ] **Step 2: Update `Commissionee` struct and constructor**

In `commissioning/commissionee.go`:

Add to the imports block:
```go
"go-matter/session"
```

In the `Commissionee` struct, add a field after `Messenger`:
```go
SessionManager *session.SessionManager
```

Replace `NewCommissionee` (after the existing `crypto.ComputeSPAKE2PVerifierData` call site logic, but as a whole replacement):
```go
func NewCommissionee(passcode uint32, salt []byte, iterations int, sm *session.SessionManager) (*Commissionee, error) {
	if sm == nil {
		return nil, errors.New("commissionee: session manager must not be nil")
	}
	w0, L, err := crypto.ComputeSPAKE2PVerifierData(passcode, salt, iterations)
	if err != nil {
		return nil, fmt.Errorf("commissionee: derive verifier: %w", err)
	}
	return &Commissionee{
		State:          StateIdle,
		SessionManager: sm,
		Salt:           append([]byte(nil), salt...),
		Iterations:     uint32(iterations),
		W0:             w0,
		L:              L,
	}, nil
}
```

- [ ] **Step 3: Update `pasePair` test helper and existing test call sites**

In `commissioning/commissioning_test.go`:

Add `"go-matter/session"` to the imports.

Replace the `pasePair` helper. The helper now constructs two `*session.SessionManager` instances and returns them so individual tests can inspect post-PASE state:

```go
func pasePair(t *testing.T, devicePasscode, controllerPasscode uint32) (
	*Commissioner, *Commissionee, *session.SessionManager, *session.SessionManager, error,
) {
	t.Helper()
	salt := []byte("SPAKE2P Key Salt")
	const iterations = 1000
	commissionerSM := session.NewSessionManager(nil)
	commissioneeSM := session.NewSessionManager(nil)
	commissionee, err := NewCommissionee(devicePasscode, salt, iterations, commissioneeSM)
	if err != nil {
		t.Fatal(err)
	}
	commissioner := NewCommissioner(nil, commissionerSM)
	deviceMsg, controllerMsg := &loopMessenger{}, &loopMessenger{}
	commissionee.Messenger, commissioner.Messenger = deviceMsg, controllerMsg
	deviceMsg.deliver = commissioner.HandleMessage
	controllerMsg.deliver = commissionee.HandleMessage
	return commissioner, commissionee, commissionerSM, commissioneeSM, commissioner.StartPASE(controllerPasscode)
}
```

Update `TestPASE_Loopback`:
```go
func TestPASE_Loopback(t *testing.T) {
	const passcode = uint32(12345678)
	commissioner, commissionee, _, _, err := pasePair(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}
	// ... rest unchanged ...
```

Update `TestPASE_WrongPasscode`:
```go
func TestPASE_WrongPasscode(t *testing.T) {
	commissioner, commissionee, _, _, err := pasePair(t, 12345678, 99999999)
	// ... rest unchanged ...
```

Update `TestCommissioner_HandleMessage_Errors` — inside the loop, replace `c := NewCommissioner(nil)` with:
```go
c := NewCommissioner(nil, session.NewSessionManager(nil))
```

- [ ] **Step 4: Update controller sample**

In `samples/commissioning/controller/main.go`:

Add `"go-matter/session"` to the imports.

Replace the `commissioner := ...` line (around line 33):
```go
sm := session.NewSessionManager(nil)
commissioner := commissioning.NewCommissioner(&controllerMessenger{tm: tm, deviceAddr: deviceAddr}, sm)
```

- [ ] **Step 5: Update device sample**

In `samples/commissioning/device/main.go`:

Add `"go-matter/session"` to the imports.

Replace the `commissionee, err := commissioning.NewCommissionee(...)` call (around line 30):
```go
sm := session.NewSessionManager(nil)
commissionee, err := commissioning.NewCommissionee(
	12345678, []byte("SPAKE2P Key Salt"), 1000, sm)
```

- [ ] **Step 6: Verify everything still builds and tests still pass**

Run: `go build ./...`
Expected: clean build.

Run: `go test ./...`
Expected: all tests pass (we have NOT yet added install logic, so existing tests should be untouched in behaviour).

- [ ] **Step 7: Commit**

```bash
git add session/session.go commissioning/commissioner.go commissioning/commissionee.go commissioning/commissioning_test.go samples/commissioning/controller/main.go samples/commissioning/device/main.go
git commit -m "Require SessionManager in Commissioner/Commissionee constructors

Wires the dependency through every call site (samples, tests, helper)
without yet performing the install. Install logic follows in the next
commits."
```

---

## Task 3: Install secure session on Commissioner side (TDD)

**Files:**
- Modify: `commissioning/commissioning_test.go` (new test asserting Commissioner side)
- Modify: `commissioning/commissioner.go` (install in `handlePake2`)

- [ ] **Step 1: Write failing test**

In `commissioning/commissioning_test.go`, add a new test after `TestPASE_Loopback`:

```go
func TestPASE_InstallsSecureSession_Commissioner(t *testing.T) {
	const passcode = uint32(12345678)
	commissioner, _, commissionerSM, _, err := pasePair(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}

	s, ok := commissionerSM.Session(commissioner.SessionID)
	if !ok {
		t.Fatalf("commissioner session %d not installed", commissioner.SessionID)
	}
	if s.LocalNodeID != session.UnspecifiedNodeID || s.PeerNodeID != session.UnspecifiedNodeID {
		t.Errorf("PASE NodeIDs must be UnspecifiedNodeID, got local=%d peer=%d", s.LocalNodeID, s.PeerNodeID)
	}
	if len(s.EncryptKey) != 16 || len(s.DecryptKey) != 16 || len(s.AttestationChallenge) != 16 {
		t.Errorf("expected three 16-byte keys, got encrypt=%d decrypt=%d attestation=%d",
			len(s.EncryptKey), len(s.DecryptKey), len(s.AttestationChallenge))
	}
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `go test -v -run TestPASE_InstallsSecureSession_Commissioner ./commissioning/`
Expected: FAIL with "commissioner session 12345 not installed".

- [ ] **Step 3: Implement install in `handlePake2`**

In `commissioning/commissioner.go`, modify `handlePake2`. Locate the block:

```go
if c.Ke, err = c.prover.SharedKey(); err != nil {
    return err
}

out, err := c.buildFrame(message.OpcodePASEPake3, frame.Header.MessageCounter, &Pake3{CA: cA})
```

Insert the install step between `SharedKey` and `buildFrame`:

```go
if c.Ke, err = c.prover.SharedKey(); err != nil {
    return err
}

keys, err := crypto.DeriveSessionKeysFromKe(c.Ke)
if err != nil {
    return fmt.Errorf("commissioner: derive session keys: %w", err)
}
c.SessionManager.InstallSecureSession(
    c.SessionID,
    session.UnspecifiedNodeID, session.UnspecifiedNodeID,
    keys, session.RoleInitiator,
)

out, err := c.buildFrame(message.OpcodePASEPake3, frame.Header.MessageCounter, &Pake3{CA: cA})
```

(Ensure `"go-matter/session"` is in the imports — added in Task 2.)

- [ ] **Step 4: Run test, verify it passes**

Run: `go test -v -run TestPASE_InstallsSecureSession_Commissioner ./commissioning/`
Expected: PASS.

Run: `go test ./...`
Expected: all tests pass (existing PASE loopback tests should still pass because install is additive).

- [ ] **Step 5: Commit**

```bash
git add commissioning/commissioner.go commissioning/commissioning_test.go
git commit -m "Install PASE-secure session on commissioner after Pake2

Derives I2R/R2I/AttestationChallenge from Ke and registers the session
in the SessionManager keyed by the commissioner's chosen session ID, with
RoleInitiator so EncryptKey resolves to I2R. NodeIDs are UnspecifiedNodeID
per the connectedhomeip reference impl."
```

---

## Task 4: Install secure session on Commissionee side (TDD)

**Files:**
- Modify: `commissioning/commissioning_test.go` (new test asserting Commissionee side + key mirroring)
- Modify: `commissioning/commissionee.go` (install in `handlePake3`)

- [ ] **Step 1: Write failing test**

In `commissioning/commissioning_test.go`, add a new test below the commissioner-side one:

```go
func TestPASE_InstallsSecureSession_Commissionee(t *testing.T) {
	const passcode = uint32(12345678)
	commissioner, commissionee, commissionerSM, commissioneeSM, err := pasePair(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}

	commSess, ok := commissionerSM.Session(commissioner.SessionID)
	if !ok {
		t.Fatalf("commissioner session not installed (Task 3 precondition)")
	}
	devSess, ok := commissioneeSM.Session(commissionee.SessionID)
	if !ok {
		t.Fatalf("commissionee session %d not installed", commissionee.SessionID)
	}

	if devSess.LocalNodeID != session.UnspecifiedNodeID || devSess.PeerNodeID != session.UnspecifiedNodeID {
		t.Errorf("PASE NodeIDs must be UnspecifiedNodeID, got local=%d peer=%d", devSess.LocalNodeID, devSess.PeerNodeID)
	}

	if !bytes.Equal(commSess.EncryptKey, devSess.DecryptKey) {
		t.Errorf("commissioner EncryptKey must mirror commissionee DecryptKey (I2R): %x vs %x",
			commSess.EncryptKey, devSess.DecryptKey)
	}
	if !bytes.Equal(commSess.DecryptKey, devSess.EncryptKey) {
		t.Errorf("commissioner DecryptKey must mirror commissionee EncryptKey (R2I): %x vs %x",
			commSess.DecryptKey, devSess.EncryptKey)
	}
	if !bytes.Equal(commSess.AttestationChallenge, devSess.AttestationChallenge) {
		t.Errorf("AttestationChallenge must match across peers: %x vs %x",
			commSess.AttestationChallenge, devSess.AttestationChallenge)
	}
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `go test -v -run TestPASE_InstallsSecureSession_Commissionee ./commissioning/`
Expected: FAIL with "commissionee session 23456 not installed".

- [ ] **Step 3: Implement install in `handlePake3`**

In `commissioning/commissionee.go`, modify `handlePake3`. Locate the block:

```go
ke, err := c.verifier.SharedKey()
if err != nil {
    return err
}
c.Ke = ke
c.State = StateComplete
return nil
```

Replace it with:

```go
ke, err := c.verifier.SharedKey()
if err != nil {
    return err
}
c.Ke = ke

keys, err := crypto.DeriveSessionKeysFromKe(c.Ke)
if err != nil {
    return fmt.Errorf("commissionee: derive session keys: %w", err)
}
c.SessionManager.InstallSecureSession(
    c.SessionID,
    session.UnspecifiedNodeID, session.UnspecifiedNodeID,
    keys, session.RoleResponder,
)

c.State = StateComplete
return nil
```

(Ensure `"go-matter/session"` is in the imports — added in Task 2.)

- [ ] **Step 4: Run test, verify it passes**

Run: `go test -v -run TestPASE_InstallsSecureSession ./commissioning/`
Expected: PASS for both commissioner and commissionee variants.

Run: `go test ./...`
Expected: full suite green.

- [ ] **Step 5: Commit**

```bash
git add commissioning/commissionee.go commissioning/commissioning_test.go
git commit -m "Install PASE-secure session on commissionee after Pake3

Mirror of the commissioner-side install with RoleResponder, so I2R/R2I
keys resolve in the reversed direction. The handshake now produces a
fully usable session on both peers."
```

---

## Task 5: Cross-encrypt round-trip verification

**Files:**
- Modify: `commissioning/commissioning_test.go` (new test driving AEAD across both peers)

This test exercises the *whole* point of §21: that the installed sessions actually decrypt each other's traffic. It should pass on first run — no implementation change needed — but its absence would let a role-swap regression slip through unnoticed.

- [ ] **Step 1: Add the cross-encrypt test**

In `commissioning/commissioning_test.go`, add the helper and test below the install tests. (Note: it uses `message.Header.Marshal` to produce both AAD and nonce input — same pattern used in `session/session_test.go`'s `buildHeader`.)

```go
// buildSecuredHeader produces the wire bytes of a minimal unicast
// secured-frame header. The bytes act both as AEAD AAD and as the input
// from which both peers reconstruct the AES-CCM nonce. For PASE-secure
// sessions the S-flag is not set, so SourceNodeID is implicit zero on
// the wire (matching connectedhomeip's secure-session send path).
func buildSecuredHeader(t *testing.T, destSessionID uint16, counter uint32) []byte {
	t.Helper()
	h := message.Header{
		SessionID:      destSessionID,
		SecurityFlags:  message.SessionTypeUnicast,
		MessageCounter: counter,
	}
	b, err := h.Marshal()
	if err != nil {
		t.Fatalf("Header.Marshal: %v", err)
	}
	return b
}

func TestPASE_CrossEncryptRoundtrip(t *testing.T) {
	const passcode = uint32(12345678)
	commissioner, commissionee, commissionerSM, commissioneeSM, err := pasePair(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}

	// Commissioner → Commissionee.
	{
		plaintext := []byte("hello from commissioner")
		commSess, _ := commissionerSM.Session(commissioner.SessionID)
		counter, err := commSess.NextOutboundCounter()
		if err != nil {
			t.Fatalf("commissioner NextOutboundCounter: %v", err)
		}
		// Frame's SessionID field carries the peer's chosen ID (so the
		// peer routes the frame to its own table entry on receipt).
		header := buildSecuredHeader(t, commissionee.SessionID, counter)

		ct, err := commissionerSM.EncryptPayload(commissioner.SessionID, plaintext, header)
		if err != nil {
			t.Fatalf("commissioner EncryptPayload: %v", err)
		}
		if bytes.Equal(ct, plaintext) {
			t.Fatalf("ciphertext equals plaintext: AEAD did not run")
		}
		pt, err := commissioneeSM.DecryptPayload(commissionee.SessionID, ct, header)
		if err != nil {
			t.Fatalf("commissionee DecryptPayload (forward): %v", err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("forward roundtrip mismatch: got %q want %q", pt, plaintext)
		}
	}

	// Commissionee → Commissioner.
	{
		plaintext := []byte("hello back from commissionee")
		devSess, _ := commissioneeSM.Session(commissionee.SessionID)
		counter, err := devSess.NextOutboundCounter()
		if err != nil {
			t.Fatalf("commissionee NextOutboundCounter: %v", err)
		}
		header := buildSecuredHeader(t, commissioner.SessionID, counter)

		ct, err := commissioneeSM.EncryptPayload(commissionee.SessionID, plaintext, header)
		if err != nil {
			t.Fatalf("commissionee EncryptPayload: %v", err)
		}
		pt, err := commissionerSM.DecryptPayload(commissioner.SessionID, ct, header)
		if err != nil {
			t.Fatalf("commissioner DecryptPayload (reverse): %v", err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("reverse roundtrip mismatch: got %q want %q", pt, plaintext)
		}
	}
}
```

- [ ] **Step 2: Run test, verify it passes**

Run: `go test -v -run TestPASE_CrossEncryptRoundtrip ./commissioning/`
Expected: PASS in both directions.

Run: `go test ./...`
Expected: full suite green.

- [ ] **Step 3: Commit**

```bash
git add commissioning/commissioning_test.go
git commit -m "Verify cross-peer AES-CCM roundtrip over PASE session

Locks in that the role-conditional key selection inside
InstallSecureSession resolves I2R/R2I correctly: commissioner ciphertext
opens on commissionee and vice versa. This is the test that would catch
a swapped-role regression."
```

---

## Task 6: Sample logging on PASE completion

**Files:**
- Modify: `samples/commissioning/controller/main.go`
- Modify: `samples/commissioning/device/main.go`

- [ ] **Step 1: Controller log line**

In `samples/commissioning/controller/main.go`, inside the `tm.Start(func(frame, from) {...})` handler, after the existing `fmt.Printf("Commissioner state=...")` line, append:

```go
if commissioner.State == commissioning.StateComplete {
	if s, ok := sm.Session(commissioner.SessionID); ok {
		fmt.Printf("Commissioner installed PASE-secure session id=%d attestationPrefix=%x\n",
			commissioner.SessionID, s.AttestationChallenge[:4])
	}
}
```

- [ ] **Step 2: Device log line**

In `samples/commissioning/device/main.go`, inside the `tm.Start(func(frame, from) {...})` handler, after the existing `fmt.Printf("Commissionee state=...")` line, append:

```go
if commissionee.State == commissioning.StateComplete {
	if s, ok := sm.Session(commissionee.SessionID); ok {
		fmt.Printf("Commissionee installed PASE-secure session id=%d attestationPrefix=%x\n",
			commissionee.SessionID, s.AttestationChallenge[:4])
	}
}
```

- [ ] **Step 3: Smoke-test the samples**

In one terminal:
```bash
go run samples/commissioning/device/main.go
```
Expected: prints `Device listening on 5540...`.

In another terminal:
```bash
go run samples/commissioning/controller/main.go
```
Expected:
- Several `Controller <- ...` / `Commissioner state=...` lines.
- A final `Commissioner installed PASE-secure session id=12345 attestationPrefix=XXXXXXXX`.

On the device side:
- Several `Device <- ...` / `Commissionee state=...` lines.
- A `Commissionee installed PASE-secure session id=23456 attestationPrefix=XXXXXXXX`.

The two `attestationPrefix` values MUST match (both peers derived the same AttestationChallenge from the same Ke).

Kill both processes with Ctrl-C.

- [ ] **Step 4: Commit**

```bash
git add samples/commissioning/controller/main.go samples/commissioning/device/main.go
git commit -m "Log PASE-secure session install in samples

Both samples now confirm post-Pake3 that the SessionManager holds the
expected entry. The matching AttestationChallenge prefix is the visible
proof that the §21 handoff worked end-to-end over real UDP."
```

---

## Task 7: Update TODO.md

**Files:**
- Modify: `TODO.md`

- [ ] **Step 1: Update the Snapshot row for `commissioning/`**

In `TODO.md`, find the row in the Snapshot table starting with `| ` + `` `commissioning/` ``. Replace its "Notes" cell. The current text says:

```
**Pending**: `Commissioner.SessionKeys()` / `Commissionee.SessionKeys()` accessors and the `SessionManager.InstallSecureSession` handoff from `Ke` (now that §12 lands the API); `Commissioner.StartCASE` is still a stub.
```

Replace that pending sentence with:

```
**Pending**: `Commissioner.StartCASE` is still a stub (Phase 7).
```

The rest of the cell (covering Pake3 completion, `Ke`, wrong-passcode test) stays.

- [ ] **Step 2: Update the bridge sentence under the snapshot table**

Find the paragraph that begins "PASE produces a working `Ke` and `session.SessionManager` now actually encrypts...". Replace its final sentence:

```
The last bridge to secured traffic is §21's `Ke → keys → SessionManager.InstallSecureSession` handoff from both `Commissioner` and `Commissionee` (now unblocked by §12), plus the `transport` flip from "pass-through" to "call `MessageSecurity` on every frame."
```

With:

```
The remaining bridge to secured traffic is the `transport` flip from "pass-through" to "call `MessageSecurity` on every frame" (Phase 5, §17-18); the PASE-derived session itself is now installed automatically inside `Commissioner.handlePake2` / `Commissionee.handlePake3`.
```

- [ ] **Step 3: Mark §21 done in Phase 6**

In Phase 6, find the bullet `21. **Derive session keys from `Ke` and hand to `SessionManager`** — _partial_.` and rewrite it as:

```
21. ~~**Derive session keys from `Ke` and hand to `SessionManager`**~~ — done. `crypto.DeriveSessionKeysFromKe(ke)` expands `Ke` per §4.13.2.1; `Commissioner.handlePake2` and `Commissionee.handlePake3` install the derived `crypto.SessionKeys` via `SessionManager.InstallSecureSession` keyed by each peer's own chosen session ID, with role-resolved I2R/R2I. NodeIDs are `session.UnspecifiedNodeID` (= 0) per `connectedhomeip`'s `kPASE` invariants. Cross-peer AES-CCM round-trip is locked by `TestPASE_CrossEncryptRoundtrip`. The follow-on `transport` flip from pass-through to `MessageSecurity` is Phase 5 (§17-18).
```

- [ ] **Step 4: Update the "Recommended order" list**

In the strict dependency order list near the bottom, find item 9: `9. **§21** — HKDF `Ke` → `(I2RKey, R2IKey, AttestationChallenge)` and `SessionManager.InstallSecureSession` handoff. _Partial_...`. Replace it with:

```
9. ~~**§21** — `Ke → SessionKeys → InstallSecureSession` handoff.~~ **Done.** Both `Commissioner` and `Commissionee` install the PASE-secure session automatically; cross-peer AES-CCM round-trip is locked.
```

- [ ] **Step 5: Verify the file still parses cleanly**

Run: `git diff TODO.md | head -100`
Expected: only the four edits above. No accidental table-formatting damage.

- [ ] **Step 6: Commit**

```bash
git add TODO.md
git commit -m "TODO: mark §21 done — PASE session handoff fully wired

PASE-derived keys are now installed automatically in SessionManager on
both peers after Pake2/Pake3, with the cross-encrypt round-trip locked
by test. Updates snapshot, Phase 6 entry, and recommended order."
```

---

## Final Verification

After all tasks complete:

- [ ] `go build ./...` — clean.
- [ ] `go test ./...` — green, with the three new tests visible:
  - `TestPASE_InstallsSecureSession_Commissioner`
  - `TestPASE_InstallsSecureSession_Commissionee`
  - `TestPASE_CrossEncryptRoundtrip`
- [ ] Manual sample smoke-test (Task 6 Step 3) — both peers print matching `attestationPrefix`.
- [ ] `git log --oneline -8` — seven new commits, in the order Tasks 1-7.
- [ ] `TODO.md` reflects §21 complete; only `Commissioner.StartCASE` still pending in commissioning.
