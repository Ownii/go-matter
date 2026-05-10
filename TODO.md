# Project TODO — go-matter

A current-state audit and a recommended order of work to get from the current scaffolding to a working Matter SDK. Last refreshed: 2026-05-10.

## Snapshot

| Area | State | Notes |
|---|---|---|
| `tlv/` | **Working** | Encoder + decoder + struct tag reflection; only package with tests. Edge cases (FullyQualified tags, List vs Array, floats) are gaps. |
| `message/` | **Working** | Matter Message Header + Payload Header encode/decode + fluent `Builder`. Round-trip tested. Secured-frame decryption hook is a TODO. |
| `crypto/` | **Partial** | SPAKE2+ Prover/Verifier landed (vendored from `tom-code/gomat`, BSD-2-Clause; PBKDF2 + (w0, L) verifier-data helpers; round-trip + locked-transcript tests). AES-CCM (13-byte nonce, 16-byte tag) now wired through `github.com/pion/dtls/v3/pkg/crypto/ccm`; round-trip + tamper + locked-vector tests cover it. HKDF still fixed 16 bytes; `NonceGenerator.NextNonce` still returns `nil`. |
| `transport/` | **Partial** | UDP send/receive operates on `*message.Frame`. No MRP, no encryption hookup. |
| `session/` | **Stubbed** | `EncryptPayload`/`DecryptPayload` are pass-through. No key derivation, no counter management, no replay window. |
| `commissioning/` | **PASE complete** | Full 5-message PASE handshake (`PBKDFParamRequest` → `Pake3`) runs end-to-end in `commissioner.go` / `commissionee.go`; both sides reach `StateComplete` with matching 16-byte `Ke`. Wrong-passcode rejection at `VerifyConfirmationB` is tested. **Pending**: HKDF `Ke` → `(I2RKey, R2IKey, AttestationChallenge)` and handoff to `SessionManager`; `Commissioner.StartCASE` is still a stub. |
| `discovery/` | **Stubbed** | mDNS advertiser + browser are `return nil` shells. |
| `interaction/` | **Stubbed** | Read/Write request handlers and senders are TODOs. No Subscribe/Invoke. |
| `datamodel/` + `model/` | **Skeleton** | Types exist; `Attribute` carries metadata only — no value storage. `DataStore.ReadAttribute` returns `nil, nil`. |
| `samples/` | **Demo only** | Controller + device drive the full PASE handshake over UDP loopback; both sides log state transitions and the negotiated session ID. Nothing runs after Pake3 (no secured frames, no Interaction Model). |
| Tests | `tlv/` + `message/` + `crypto/` + `commissioning/` | `interaction/`, `model/`, `transport/`, `session/`, `discovery/` still have zero coverage. |
| Build/CI | None | No `make`, no GitHub Actions, no lint config. `go build ./...` and `go test ./...` pass. |

PASE produces a working `Ke` on both sides but nothing post-handshake is encrypted yet: `NonceGenerator.NextNonce` returns `nil`, `crypto.HKDF` is fixed at 16 bytes, and `session.SessionManager.{Encrypt,Decrypt}Payload` are pass-throughs. AES-CCM is now real, so the next blockers are §9 (`NextNonce`) and §11 (variable-length HKDF) before Phase 4 can wire session keys end-to-end.

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
9. **Implement `NonceGenerator.NextNonce`** per Matter §5.3.1: `Security Flags (1) | Message Counter (4) | Source Node ID (8)` — note the spec says 13 bytes, not the layout currently in the comment. Cover with a known-vector test.
10. ~~**Wire `jtejido/spake2plus`** into `crypto.SPAKE2PContext`.~~ **DONE** — vendored from `tom-code/gomat` (BSD-2-Clause) instead, since `jtejido/spake2plus` hides the intermediate values Matter §3.10's TT requires. `crypto.SPAKE2PProver` / `crypto.SPAKE2PVerifier` expose `ComputePA`, `ComputePB`, `Finalize`, `ConfirmationA/B`, `VerifyConfirmation*`, `SharedKey`. Follow-ups: cross-check w0/w1 byte-width against `connectedhomeip/src/crypto/tests/`, and validate end-to-end against a real Matter device.
11. **HKDF: return `io.Reader` or accept length parameter**. The fixed 16-byte output in `DeriveKeys` is wrong for Matter, which derives multiple keys (I2RKey, R2IKey, AttestationChallenge) from one secret.

## Phase 4 — Session layer (depends on 2, 3)

12. **Replace `Session.Keys []byte`** with a typed struct: `{ I2RKey, R2IKey, AttestationChallenge []byte }`. Track direction per encrypt/decrypt call.
13. **Implement `EncryptPayload`/`DecryptPayload`** using AES-CCM, the per-direction key, and a nonce assembled from the message header.
14. **Counter management**: bump `OutCounter` on encrypt; validate `InCounter` on decrypt with a sliding replay window (Matter spec recommends 32 entries).
15. **Unsecured session path** for handshake messages (PASE/CASE messages travel unencrypted before keys exist) — pick a sentinel session ID 0.
16. **Lifecycle**: `SessionManager.RemoveSession`, expiry, eviction; today `sessions` only grows.

## Phase 5 — Transport reliability (depends on 2)

17. **MRP (Message Reliability Protocol)** in `transport/`:
    - Per-exchange retransmission with backoff (`MRP_BACKOFF_BASE`, `MRP_BACKOFF_THRESHOLD` from spec).
    - Standalone Ack messages.
    - Duplicate detection by `(SourceNodeID, MessageCounter)`.
    - The `unackedMessages map[uint32]interface{}` field on `TransportManager` is the placeholder for this — give it a real type.
18. **Exchange Manager** — `transport` (or a new `exchange/` package) needs to track active exchanges and route inbound messages by Exchange ID. Today, the `ReadHandler` is called blindly.

## Phase 6 — Complete PASE — **DONE**

19. ~~**`PBKDFParamResponse` struct + handler**~~ — done. `commissioning/messages.go` defines `PBKDFParamResponse` + nested `PBKDFParamSet`; `Commissionee.handlePBKDFParamRequest` decodes the request and replies with salt/iterations/responder-random/session-ID.
20. ~~**Pake1 / Pake2 / Pake3 structs and state transitions**~~ — done. Wire structs in `commissioning/messages.go`; `commissioning.paseContext` builds the SPAKE2+ context input (`"CHIP PAKE V1 Commissioning" || PBKDFParamRequest || PBKDFParamResponse`, Matter §3.10) and `crypto.spakeFinalize` hashes it. Commissioner runs `Spake2pW0W1FromPasscode → NewSPAKE2PProver → ComputePA → Finalize(pB) → VerifyConfirmationB → ConfirmationA`. Commissionee runs `NewSPAKE2PVerifier(W0,L,ctx) → ComputePB(pA) → Finalize → ConfirmationB → VerifyConfirmationA`. Both reach `StateComplete` with the same 16-byte `Ke`.
21. **Derive session keys from `Ke` and hand to `SessionManager`** — _pending_. `Ke` is produced and stored on `Commissioner.Ke` / `Commissionee.Ke` but no HKDF expansion to `(I2RKey, R2IKey, AttestationChallenge)` and no `SessionManager.CreateSession` handoff yet. Blocked by Phase 3 §11 (variable-length HKDF) and Phase 4 §12-13 (typed key struct + AES-CCM encrypt/decrypt).
22. ~~**Wire commissionee receive path**~~ — done. The device sample (`samples/commissioning/device/main.go`) dispatches into `Commissionee.HandleMessage`, the controller sample consumes responses via `Commissioner.HandleMessage`, and a `deviceMessenger` sends replies back to the originating UDP peer.
23. ~~**Tests**~~ — done. `commissioning/commissioning_test.go` covers `PBKDFParamResponse` TLV round-trip, `omitempty` on `Params`, full in-memory PASE loopback (`TestPASE_Loopback`), wrong-passcode rejection at `VerifyConfirmationB` (`TestPASE_WrongPasscode`), and `Commissioner.HandleMessage` error paths.

## Phase 7 — CASE + Fabrics (depends on 6, plus new crypto)

24. **NOC / ICAC / RCAC certificate handling** in `crypto/` (X.509 parsing, Matter-specific extensions, signature verification with P-256).
25. **Fabric table** in `model.Fabric` — store RootCert, NOC, ICAC, fabric ID, node ID, IPK. Persist (see Phase 9).
26. **CASE handshake messages** (Sigma1, Sigma2, Sigma3) in `commissioning/`. Reuse the framing/transcript pattern from PASE.
27. **`Commissioner.StartCASE`** body (currently a 3-line stub in `commissioning/commissioner.go`).

## Phase 8 — Discovery (independent, can run in parallel with 4-6)

28. **mDNS advertiser** (`discovery.Advertiser`): publish `_matterc._udp.local.` for commissionable devices and `_matter._tcp.local.` for operational. TXT records per Matter §4.3.
29. **mDNS browser** (`discovery.Browser`): emit `DiscoveredDevice` on the channel returned from `Browse`.
30. **Pick a library**: `github.com/grandcat/zeroconf` or `github.com/hashicorp/mdns`. Add it to `go.mod`. Avoid rolling your own unless absolutely necessary.

## Phase 9 — Interaction Model (depends on 4, 6)

31. **Interaction Model message types**: `ReadRequestMessage`, `ReportDataMessage`, `WriteRequestMessage`, `WriteResponseMessage`, `InvokeRequestMessage`, `InvokeResponseMessage`, `SubscribeRequestMessage`, `SubscribeResponseMessage`, `StatusResponseMessage`, `TimedRequestMessage`. Each as a Go struct with TLV tags.
32. **Path types**: `AttributePathIB`, `CommandPathIB`, `EventPathIB`. Handle wildcards (NodeID/Endpoint/Cluster/Attribute = nullable).
33. **Dispatch**: in `InteractionModel.HandleReadRequest`, parse paths, walk `AttributeStore`, build `AttributeReportIB` list, send `ReportData`.
34. **Status codes** (`Success`, `UnsupportedAttribute`, `InvalidAction`, etc.) — define an enum and use it for errors.
35. **Subscriptions**: subscription manager that holds active subscriptions per session and emits reports on attribute change. This requires a notification channel from `model.DataStore`.
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
6. **§9** — Real `NextNonce`.
7. **§11** — HKDF returning variable-length output.
8. **§12-15** — Session keys, encrypt/decrypt, counter window, unsecured session.
9. **§21** — HKDF `Ke` → `(I2RKey, R2IKey, AttestationChallenge)` and `SessionManager.CreateSession` handoff. (This is the lone PASE follow-up; depends on §11 + §12.)
10. **§17-18** — MRP and Exchange Manager.
11. **§1-5** — Phase 1 TLV polish (insert here once you've felt the pain points from real protocol work).
12. **§28-30** — mDNS, in parallel with the next steps.
13. **§24-27** — CASE + Fabrics.
14. **§31-36** — Interaction Model.
15. **§37-40** — Data model + persistence + ACL.
16. **§41-45** — CI, lint, integration sample, codegen.

Items §1-5 (TLV polish) are deliberately deferred: the current encoder works for everything through PASE, and you'll have a much better sense of which gaps actually matter once you've encoded CASE Sigma1/2/3 and a few Interaction Model structs.
