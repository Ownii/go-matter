# Project TODO — go-matter

A current-state audit and a recommended order of work to get from the current scaffolding to a working Matter SDK. Last refreshed: 2026-05-11.

## Snapshot

| Area | State | Notes |
|---|---|---|
| `tlv/` | **Working** | Encoder + decoder + struct tag reflection; only package with tests. Edge cases (FullyQualified tags, List vs Array, floats) are gaps. |
| `message/` | **Working** | Matter Message Header + Payload Header encode/decode + fluent `Builder`. Round-trip tested. Secured-frame decryption hook is a TODO. |
| `crypto/` | **Partial** | SPAKE2+ Prover/Verifier landed (vendored from `tom-code/gomat`, BSD-2-Clause; PBKDF2 + (w0, L) verifier-data helpers; round-trip + locked-transcript tests). AES-CCM (13-byte nonce, 16-byte tag) wired through `github.com/pion/dtls/v3/pkg/crypto/ccm`. `BuildNonce` + `NonceGenerator` produce the §5.3.1 nonce layout with a counter-exhaustion guard and locked-vector test. `HKDF(secret, salt, info, length)` is variable-length (RFC 5869 A.1/A.2/A.3 vectors). `DeriveSessionKeysFromKe` expands `Ke` to `(I2RKey, R2IKey, AttestationChallenge)` per §4.13.2.1 (regression-locked vector). |
| `transport/` | **Partial** | UDP send/receive operates on `*message.Frame`. No MRP, no encryption hookup. |
| `session/` | **Working (unicast)** | Typed `crypto.SessionKeys` install via `SessionManager.InstallSecureSession(id, local, peer, keys, role)`; role resolves I2R/R2I once. `EncryptPayload`/`DecryptPayload` drive AES-128-CCM with `crypto.BuildNonce` from the cleartext header (also AAD). Outbound counter via `Session.NextOutboundCounter` (returns `crypto.ErrCounterExhausted`). 32-entry sliding replay window (Matter §4.5.4.2) commits only after AEAD auth — tampered frames cannot open gaps. Session ID 0 is pass-through. Group sessions + `MSG_COUNTER_SYNC_REQ` deferred. |
| `commissioning/` | **PASE complete** | Full 5-message PASE handshake (`PBKDFParamRequest` → `Pake3`) runs end-to-end in `commissioner.go` / `commissionee.go`; both sides reach `StateComplete` with matching 16-byte `Ke`. Wrong-passcode rejection at `VerifyConfirmationB` is tested. **Pending**: `Commissioner.SessionKeys()` / `Commissionee.SessionKeys()` accessors and the `SessionManager.InstallSecureSession` handoff from `Ke` (now that §12 lands the API); `Commissioner.StartCASE` is still a stub. |
| `discovery/` | **Stubbed** | mDNS advertiser + browser are `return nil` shells. |
| `interaction/` | **Stubbed** | Read/Write request handlers and senders are TODOs. No Subscribe/Invoke. |
| `datamodel/` + `model/` | **Skeleton** | Types exist; `Attribute` carries metadata only — no value storage. `DataStore.ReadAttribute` returns `nil, nil`. |
| `samples/` | **Demo only** | Controller + device drive the full PASE handshake over UDP loopback; both sides log state transitions and the negotiated session ID. Nothing runs after Pake3 (no secured frames, no Interaction Model). |
| Tests | `tlv/` + `message/` + `crypto/` + `commissioning/` + `session/` | `interaction/`, `model/`, `transport/`, `discovery/` still have zero coverage. |
| Build/CI | None | No `make`, no GitHub Actions, no lint config. `go build ./...` and `go test ./...` pass. |

PASE produces a working `Ke` and `session.SessionManager` now actually encrypts: typed keys, AES-128-CCM, replay window, and a session-0 pass-through for the handshake. The last bridge to secured traffic is §21's `Ke → keys → SessionManager.InstallSecureSession` handoff from both `Commissioner` and `Commissionee` (now unblocked by §12), plus the `transport` flip from "pass-through" to "call `MessageSecurity` on every frame."

---

## Phase 1 — Foundation hardening (small, blocks nothing but cheap)

1. **TLV: float/double support** in `Encoder.encodeValue` and `Decoder` (Matter uses `0x0A`/`0x0B`).
2. **TLV: List (`0x17`) vs Array (`0x16`)** distinction. Today every Go slice becomes an Array. Add a way to opt into List for protocol fields that require it (struct tag option, e.g. `tlv:"5,list"`).
3. **TLV: FullyQualified tag round-trip**. The `// TODO: verify exact byte layout` in `tlv/tlv.go:149` is a real correctness bug; reconcile against Matter Core Spec §A.7 and add a test.
4. **TLV: bufio.Reader** behind `tlv.Reader` to avoid per-byte syscalls when reading from `net.Conn`.
5. **TLV: tests for nested containers, omitempty, byte string vs UTF-8, and integer width selection.** Currently only one happy-path struct is covered.

## Phase 2 — Matter message framing (critical, unblocks 3-7) — **DONE**

6. ~~**Add `message/` package**~~ — done. `message/` ships `Header`, `PayloadHeader`, `Frame`, a fluent `Builder`, opcode/protocol constants, and tests. Open follow-ups:
   - Secured-frame path: `Decode` currently parses the payload header from cleartext bytes; once the session layer can decrypt, `Frame.Encrypted` (or equivalent) needs to gate when the payload header is parsed.
   - `MsgCounterSyncReq`/`Resp` and full Interaction Model opcode catalogues are not yet defined.
   - Message extensions (MX flag) are recognised but the variable-length extension blob is not parsed.
7. ~~**Wire the framing into `transport.TransportManager`**~~ — done. `Send(addr, *message.Frame, reliable)` and `ReadHandler func(*message.Frame, *net.UDPAddr)`. `commissioning.StartPASE` now builds a real frame; both samples log decoded opcode + exchange ID.

## Phase 3 — Crypto primitives (unblocks 5, 6)

8. ~~**Replace the AES-GCM placeholder with AES-CCM**~~ — done. `crypto.DefaultCryptoProvider.{Encrypt,Decrypt}` now use `github.com/pion/dtls/v3/pkg/crypto/ccm` with a fixed 13-byte nonce (`MatterNonceSize`) and 16-byte tag (`MatterTagSize`); a sentinel `ErrInvalidNonceSize` rejects anything else. Coverage: round-trip across multiple plaintext lengths, tamper detection on ciphertext / tag / AAD, wrong-key + wrong-nonce rejection, invalid-nonce-size rejection, and a locked-output regression vector.
9. ~~**Implement `NonceGenerator.NextNonce`**~~ — done. `crypto.BuildNonce` assembles the 13-byte §5.3.1 layout (`SecurityFlags(1) ‖ MessageCounter(4 LE) ‖ SourceNodeID(8 LE)`); `NonceGenerator.NextNonce` increments and returns `ErrCounterExhausted` before wrapping at `math.MaxUint32`. Tests cover layout, monotonic uniqueness across 100 calls, exhaustion sticky-state, and a CCM round-trip through the generator's output.
10. ~~**Wire `jtejido/spake2plus`** into `crypto.SPAKE2PContext`.~~ **DONE** — vendored from `tom-code/gomat` (BSD-2-Clause) instead, since `jtejido/spake2plus` hides the intermediate values Matter §3.10's TT requires. `crypto.SPAKE2PProver` / `crypto.SPAKE2PVerifier` expose `ComputePA`, `ComputePB`, `Finalize`, `ConfirmationA/B`, `VerifyConfirmation*`, `SharedKey`. Follow-ups: cross-check w0/w1 byte-width against `connectedhomeip/src/crypto/tests/`, and validate end-to-end against a real Matter device.
11. ~~**HKDF: return `io.Reader` or accept length parameter**~~ — done. `crypto.HKDF(secret, salt, info, length)` runs the full RFC 5869 Extract-then-Expand pipeline over SHA-256 and returns exactly `length` bytes. The legacy `DefaultCryptoProvider.DeriveKeys` keeps its 16-byte contract by delegating to `HKDF(..., 16)`. Tests cover RFC 5869 A.1/A.2/A.3 known-answer vectors, zero-length output, and negative-length rejection.

## Phase 4 — Session layer (depends on 2, 3)

12. ~~**Replace `Session.Keys []byte`**~~ — done. `Session` now embeds typed `EncryptKey` / `DecryptKey` / `AttestationChallenge`, resolved from `crypto.SessionKeys` + `Role` at install time so the hot path never re-branches on direction.
13. ~~**Implement `EncryptPayload`/`DecryptPayload`**~~ — done. AES-128-CCM via `crypto.DefaultCryptoProvider`; the 13-byte nonce is rebuilt from the cleartext header (`SecurityFlags ‖ MessageCounter ‖ SourceNodeID`) and the header bytes themselves are the AAD (Matter §4.5.3).
14. ~~**Counter management**~~ — done. Outbound: `Session.NextOutboundCounter` is the explicit, fail-stop counter source (`crypto.ErrCounterExhausted` before wrap, §4.5.1.1). Inbound: a 32-entry sliding window per §4.5.4.2; commit is deferred until AEAD auth succeeds so tampered frames can't open replay gaps. Unicast-only — group sessions (mod-2³¹ rules + `MSG_COUNTER_SYNC_REQ`) are deferred.
15. ~~**Unsecured session path**~~ — done. `session.UnsecuredSessionID = 0`; `EncryptPayload`/`DecryptPayload` short-circuit before any table lookup, matching `docs/Messaging_Architecture.md`.
16. **Lifecycle**: `SessionManager.RemoveSession`, expiry, eviction; today `sessions` only grows. PASE sessions are short-lived; CASE sessions persist — see [`docs/Messaging_Architecture.md`](docs/Messaging_Architecture.md).

## Phase 5 — Transport reliability (depends on 2)

> **Architectural contract:** §17 and §18 are where commissioning and operational converge onto a single message-handling stack. Read [`docs/Messaging_Architecture.md`](docs/Messaging_Architecture.md) before starting either — in particular, MRP retx belongs on `ExchangeManager`, not on `TransportManager`, and the `*Exchange` type defined here is what `commissioning/`, future CASE code, and the Interaction Model all consume.

17. **MRP (Message Reliability Protocol)** on the new `ExchangeManager` (not on `transport/`; see [`docs/Messaging_Architecture.md`](docs/Messaging_Architecture.md)):
    - Per-exchange retransmission with backoff (`MRP_BACKOFF_BASE`, `MRP_BACKOFF_THRESHOLD` from spec).
    - Standalone Ack messages.
    - Duplicate detection by `(SourceNodeID, MessageCounter)`.
    - The `unackedMessages map[uint32]interface{}` field on `TransportManager` is the placeholder for this — give it a real type and move it.
18. **Exchange Manager** — new `exchange/` package, tracks active exchanges and routes inbound messages by `(SessionID, ExchangeID)`. Owns the per-exchange goroutine + retx timer. Today, the `ReadHandler` is called blindly. Defines `*Exchange { Inbox <-chan *Frame; Send(payload) error }` consumed by commissioning, CASE, and IM. See [`docs/Messaging_Architecture.md`](docs/Messaging_Architecture.md) for the contract; **after this lands, `commissioning/` must be refactored to use `*Exchange` instead of `CommissioningMessenger`.**

## Phase 6 — Complete PASE — **DONE**

19. ~~**`PBKDFParamResponse` struct + handler**~~ — done. `commissioning/messages.go` defines `PBKDFParamResponse` + nested `PBKDFParamSet`; `Commissionee.handlePBKDFParamRequest` decodes the request and replies with salt/iterations/responder-random/session-ID.
20. ~~**Pake1 / Pake2 / Pake3 structs and state transitions**~~ — done. Wire structs in `commissioning/messages.go`; `commissioning.paseContext` builds the SPAKE2+ context input (`"CHIP PAKE V1 Commissioning" || PBKDFParamRequest || PBKDFParamResponse`, Matter §3.10) and `crypto.spakeFinalize` hashes it. Commissioner runs `Spake2pW0W1FromPasscode → NewSPAKE2PProver → ComputePA → Finalize(pB) → VerifyConfirmationB → ConfirmationA`. Commissionee runs `NewSPAKE2PVerifier(W0,L,ctx) → ComputePB(pA) → Finalize → ConfirmationB → VerifyConfirmationA`. Both reach `StateComplete` with the same 16-byte `Ke`.
21. **Derive session keys from `Ke` and hand to `SessionManager`** — _partial_. Crypto half done: `crypto.DeriveSessionKeysFromKe(ke)` expands `Ke` into the typed `crypto.SessionKeys{I2RKey, R2IKey, AttestationChallenge}` per §4.13.2.1 (one HKDF-SHA-256 call, empty salt, info `"SessionKeys"`, 48 bytes split 16/16/16). Locked regression vector + AES-CCM round-trip test. Still pending: `Commissioner.SessionKeys()` / `Commissionee.SessionKeys()` accessors and the `SessionManager.InstallSecureSession(id, local, peer, keys, role)` handoff — now unblocked by §12. This handoff is the bridge from "PASE on unsecured session 0" to "post-Pake3 commissioning on the PASE-secure session" — the latter is then ordinary Interaction Model traffic per [`docs/Messaging_Architecture.md`](docs/Messaging_Architecture.md). Do not implement `ArmFailSafe`/`CSRRequest`/`AddNOC`/`CommissioningComplete` as bespoke commissioning opcodes; they are `Invoke` calls.
22. ~~**Wire commissionee receive path**~~ — done. The device sample (`samples/commissioning/device/main.go`) dispatches into `Commissionee.HandleMessage`, the controller sample consumes responses via `Commissioner.HandleMessage`, and a `deviceMessenger` sends replies back to the originating UDP peer.
23. ~~**Tests**~~ — done. `commissioning/commissioning_test.go` covers `PBKDFParamResponse` TLV round-trip, `omitempty` on `Params`, full in-memory PASE loopback (`TestPASE_Loopback`), wrong-passcode rejection at `VerifyConfirmationB` (`TestPASE_WrongPasscode`), and `Commissioner.HandleMessage` error paths.

## Phase 7 — CASE + Fabrics (depends on 6, plus new crypto)

24. **NOC / ICAC / RCAC certificate handling** in `crypto/` (X.509 parsing, Matter-specific extensions, signature verification with P-256).
25. **Fabric table** in `model.Fabric` — store RootCert, NOC, ICAC, fabric ID, node ID, IPK. Persist (see Phase 9).
26. **CASE handshake messages** (Sigma1, Sigma2, Sigma3) in `commissioning/`. Reuse the framing/transcript pattern from PASE. Like PASE, the CASE state machine consumes an `*Exchange` — do not reintroduce a CASE-specific messenger/routing path. See [`docs/Messaging_Architecture.md`](docs/Messaging_Architecture.md).
27. **`Commissioner.StartCASE`** body (currently a 3-line stub in `commissioning/commissioner.go`). Establishes the CASE-secure session that supplants the PASE-secure session for operational traffic — see [`docs/Messaging_Architecture.md`](docs/Messaging_Architecture.md) for the session-lifecycle expectations.

## Phase 8 — Discovery (independent, can run in parallel with 4-6)

28. **mDNS advertiser** (`discovery.Advertiser`): publish `_matterc._udp.local.` for commissionable devices and `_matter._tcp.local.` for operational. TXT records per Matter §4.3.
29. **mDNS browser** (`discovery.Browser`): emit `DiscoveredDevice` on the channel returned from `Browse`.
30. **Pick a library**: `github.com/grandcat/zeroconf` or `github.com/hashicorp/mdns`. Add it to `go.mod`. Avoid rolling your own unless absolutely necessary.

## Phase 9 — Interaction Model (depends on 4, 6)

> All IM handlers consume `*Exchange` (see [`docs/Messaging_Architecture.md`](docs/Messaging_Architecture.md)). Post-Pake3 commissioning opcodes (`ArmFailSafe`, `CSRRequest`, `AddNOC`, `CommissioningComplete`) are `Invoke` calls handled here, not separate commissioning messages.

31. **Interaction Model message types**: `ReadRequestMessage`, `ReportDataMessage`, `WriteRequestMessage`, `WriteResponseMessage`, `InvokeRequestMessage`, `InvokeResponseMessage`, `SubscribeRequestMessage`, `SubscribeResponseMessage`, `StatusResponseMessage`, `TimedRequestMessage`. Each as a Go struct with TLV tags.
32. **Path types**: `AttributePathIB`, `CommandPathIB`, `EventPathIB`. Handle wildcards (NodeID/Endpoint/Cluster/Attribute = nullable).
33. **Dispatch**: in `InteractionModel.HandleReadRequest`, parse paths, walk `AttributeStore`, build `AttributeReportIB` list, send `ReportData`.
34. **Status codes** (`Success`, `UnsupportedAttribute`, `InvalidAction`, etc.) — define an enum and use it for errors.
35. **Subscriptions**: subscription manager that holds active subscriptions per session and emits reports on attribute change. This requires a notification channel from `model.DataStore` — the canonical channel-based fan-out point in the architecture; see [`docs/Messaging_Architecture.md`](docs/Messaging_Architecture.md).
36. **Invoke**: command dispatch table on `Cluster`, request/response TLV structs per command.

## Phase 10 — Data model fleshing (depends on 9)

37. **Attribute value storage**: today `datamodel.Attribute` only holds metadata. Either add a `Value interface{}` field, or split into `AttributeDef` (metadata) + a value map keyed by `(Endpoint, Cluster, Attribute)` on `DataStore`.
38. **Cluster catalog** for the must-have clusters to bring up a Root Node:
    - Basic Information (0x0028)
    - General Commissioning (0x0030)
    - Network Commissioning (0x0031)
    - General Diagnostics (0x0033)
    - Operational Credentials (0x003E)
    - Access Control (0x001F)
    - Descriptor (0x001D)
39. **Persistence**: device state survives restart. Start with a JSON file under a configurable data dir; abstract behind an interface so it can be swapped later.
40. **Access control** — the `// TODO: Add access control fields` on `datamodel.Attribute` (line 31) should reference an ACL evaluated on every Read/Write/Invoke.

## Phase 11 — Tooling, CI, samples

41. **CI**: GitHub Actions workflow running `go vet`, `go test ./...`, and `staticcheck` on push.
42. **`Makefile` or `task`** with `make test`, `make device`, `make controller`, `make integration`.
43. **Linter config**: `.golangci.yml` enabling at least `govet`, `errcheck`, `staticcheck`, `gosec`.
44. **Integration sample** (`samples/integration/`): single binary that spins up a device + controller in-process and runs PASE → Read → Write end to end. The current two-process sample is good for demo but bad for CI.
45. **Cluster code generation**: once the cluster catalog grows past 5-10 entries, generate Go structs from the Matter ZAP/XML cluster definitions instead of hand-writing them.

---

## Recommended order

PASE is in. The fastest path to a Matter session that actually carries traffic is now:

```
Phase 3 (AES-CCM, NextNonce, HKDF)  →  Phase 4 (typed session keys, encrypt/decrypt, counter window)
                                                          ↓
                                          §21 (HKDF Ke → I2RKey/R2IKey, install in SessionManager)
                                                          ↓
                                          Phase 5 (MRP, Exchange Manager)
                                                          ↓
Phase 1 (TLV polish, opportunistically)   Phase 7 (CASE)   ←   Phase 8 (mDNS, parallel)
                                                          ↓
                                          Phase 9 (Interaction Model)   ←   needed before any post-PASE
                                                          ↓               commissioning step (ArmFailSafe,
                                          Phase 10 (Data model + clusters)  CSRRequest, AddNOC, etc.)
                                                          ↓
                                          Phase 11 (CI, tooling, samples)
```

Strict dependency order, single-developer flat list:

1. ~~**§6** — Add `message/` package with Matter Message Header + Payload Header.~~ **Done.**
2. ~~**§7** — Wire framing into `transport`, change `ReadHandler` signature.~~ **Done.**
3. ~~**§10** — Real SPAKE2+ context.~~ **Done.**
4. ~~**§19-20, §22-23** — PASE messages + state machine + sample wiring + integration test.~~ **Done.**
5. ~~**§8** — AES-CCM in `crypto`.~~ **Done.** Wired through `github.com/pion/dtls/v3/pkg/crypto/ccm` (MIT) with a 13-byte nonce + 16-byte tag.
6. ~~**§9** — Real `NextNonce`.~~ **Done.** `BuildNonce` + `NonceGenerator` produce the §5.3.1 layout with a counter-exhaustion guard.
7. ~~**§11** — HKDF returning variable-length output.~~ **Done.** `crypto.HKDF(secret, salt, info, length)` with RFC 5869 KATs.
8. ~~**§12-15** — Session keys, encrypt/decrypt, counter window, unsecured session.~~ **Done.** Typed `crypto.SessionKeys` + `Role` resolve I2R/R2I at install; AES-128-CCM with header-as-AAD; `Session.NextOutboundCounter` is the fail-stop counter source; 32-entry replay window commits only after AEAD auth; `UnsecuredSessionID = 0` is pass-through. Unicast-only.
9. **§21** — HKDF `Ke` → `(I2RKey, R2IKey, AttestationChallenge)` and `SessionManager.InstallSecureSession` handoff. _Partial_: `crypto.DeriveSessionKeysFromKe` done; the install handoff is the remaining step now that §12 supplies the API (`SessionManager.InstallSecureSession(id, local, peer, keys, role)`).
10. **§17-18** — MRP and Exchange Manager.
11. **§1-5** — Phase 1 TLV polish (insert here once you've felt the pain points from real protocol work).
12. **§28-30** — mDNS, in parallel with the next steps.
13. **§24-27** — CASE + Fabrics.
14. **§31-36** — Interaction Model.
15. **§37-40** — Data model + persistence + ACL.
16. **§41-45** — CI, lint, integration sample, codegen.

Items §1-5 (TLV polish) are deliberately deferred: the current encoder works for everything through PASE, and you'll have a much better sense of which gaps actually matter once you've encoded CASE Sigma1/2/3 and a few Interaction Model structs.
