# Project TODO — go-matter

A current-state audit and a recommended order of work to get from the current scaffolding to a working Matter SDK. Last refreshed: 2026-05-08.

## Snapshot

| Area | State | Notes |
|---|---|---|
| `tlv/` | **Working** | Encoder + decoder + struct tag reflection; only package with tests. Edge cases (FullyQualified tags, List vs Array, floats) are gaps. |
| `crypto/` | **Stubbed** | AES-CCM replaced with AES-GCM placeholder; SPAKE2+ wrapper holds `interface{}`; HKDF returns fixed 16 bytes; `NonceGenerator.NextNonce` returns `nil`. |
| `transport/` | **Partial** | UDP send/receive works. No MRP, no encryption hookup, no Matter message-header parsing. |
| `session/` | **Stubbed** | `EncryptPayload`/`DecryptPayload` are pass-through. No key derivation, no counter management, no replay window. |
| `commissioning/` | **Skeleton** | Only `PBKDFParamRequest` is sent. `PBKDFParamResponse` and Pake1/2/3 missing. `Commissionee.HandleMessage` is empty. CASE is one TODO. |
| `discovery/` | **Stubbed** | mDNS advertiser + browser are `return nil` shells. |
| `interaction/` | **Stubbed** | Read/Write request handlers and senders are TODOs. No Subscribe/Invoke. |
| `datamodel/` + `model/` | **Skeleton** | Types exist; `Attribute` carries metadata only — no value storage. `DataStore.ReadAttribute` returns `nil, nil`. |
| `samples/` | **Demo only** | Controller sends one `PBKDFParamRequest`; device prints bytes. No end-to-end completion path. |
| Tests | `tlv/` only | All other packages have zero coverage. |
| Build/CI | None | No `make`, no GitHub Actions, no lint config. `go build ./...` and `go test ./...` pass. |

The cross-cutting blocker that everything depends on is **the Matter Message Frame format** (Message Header + Payload Header / Exchange Header). It does not exist anywhere in the codebase yet — `transport.Send` writes the raw payload directly to UDP. Fixing this unblocks transport encryption, session counters, exchange tracking, and commissioning state.

---

## Phase 1 — Foundation hardening (small, blocks nothing but cheap)

1. **TLV: float/double support** in `Encoder.encodeValue` and `Decoder` (Matter uses `0x0A`/`0x0B`).
2. **TLV: List (`0x17`) vs Array (`0x16`)** distinction. Today every Go slice becomes an Array. Add a way to opt into List for protocol fields that require it (struct tag option, e.g. `tlv:"5,list"`).
3. **TLV: FullyQualified tag round-trip**. The `// TODO: verify exact byte layout` in `tlv/tlv.go:149` is a real correctness bug; reconcile against Matter Core Spec §A.7 and add a test.
4. **TLV: bufio.Reader** behind `tlv.Reader` to avoid per-byte syscalls when reading from `net.Conn`.
5. **TLV: tests for nested containers, omitempty, byte string vs UTF-8, and integer width selection.** Currently only one happy-path struct is covered.

## Phase 2 — Matter message framing (critical, unblocks 3-7)

6. **Add `message/` (or `frame/`) package** implementing:
   - **Message Header** (4-byte flags/security, Session ID, Message Counter, optional Source/Dest Node ID) — `Encode`/`Decode` pair.
   - **Payload Header / Exchange Header** (Exchange Flags, Protocol Opcode, Exchange ID, Protocol ID, optional Ack Counter, Vendor ID).
   - Constants for protocol IDs (Secure Channel, Interaction Model) and opcodes (`MsgCounterSyncReq`, `PBKDFParamRequest`, `PASE_Pake1`, etc.).
7. **Wire the framing into `transport.TransportManager`**: `Send` builds the wire packet from `(MessageHeader, PayloadHeader, payload)`; `Start` parses the inverse before invoking the handler. The `ReadHandler` signature should change to receive parsed headers, not raw bytes.

## Phase 3 — Crypto primitives (unblocks 5, 6)

8. **Replace the AES-GCM placeholder with AES-CCM** (13-byte nonce, 16-byte tag). `cipher.NewCCM` is unavailable in stdlib — use `golang.org/x/crypto`'s CCM or vendor a small implementation. Add round-trip tests with Matter test vectors.
9. **Implement `NonceGenerator.NextNonce`** per Matter §5.3.1: `Security Flags (1) | Message Counter (4) | Source Node ID (8)` — note the spec says 13 bytes, not the layout currently in the comment. Cover with a known-vector test.
10. **Wire `jtejido/spake2plus`** into `crypto.SPAKE2PContext`. Replace `interface{}` with concrete client/server fields. Provide `ComputePA`, `ComputePB`, `ComputeZ`, `ConfirmationHash` helpers — the names should match the PASE explainer in `docs/PASE_Explainer.md`.
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

## Phase 6 — Complete PASE (depends on 2, 3, 4, 5)

19. **`PBKDFParamResponse` struct + handler** (responder generates Salt + Iterations + Session ID; initiator stores them).
20. **Pake1 / Pake2 / Pake3 structs and state transitions** in `Commissionee.HandleMessage`. Each step must:
    - Update `c.State`.
    - Feed the on-the-wire bytes into the running **PASE transcript hash** (see explainer §"How is the Session Key calculated?").
    - Validate confirmation hashes (`cA`, `cB`).
21. **Derive session keys from `Ke`** (HKDF over transcript) and hand them to `SessionManager.CreateSession` so subsequent traffic is encrypted.
22. **Wire commissionee receive path**: `samples/commissioning/device/main.go:35` already calls `HandleMessage` — once 19-21 are done, it should drive a real response. Update the controller sample to consume the response.
23. **Tests**: a unit test for each PASE message round-trip (encode → decode → re-encode), and an in-process integration test that runs commissioner + commissionee against each other without UDP.

## Phase 7 — CASE + Fabrics (depends on 6, plus new crypto)

24. **NOC / ICAC / RCAC certificate handling** in `crypto/` (X.509 parsing, Matter-specific extensions, signature verification with P-256).
25. **Fabric table** in `model.Fabric` — store RootCert, NOC, ICAC, fabric ID, node ID, IPK. Persist (see Phase 9).
26. **CASE handshake messages** (Sigma1, Sigma2, Sigma3) in `commissioning/`. Reuse the framing/transcript pattern from PASE.
27. **`Commissioner.StartCASE`** body (currently one TODO at `commissioning/commissioning.go:97`).

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

The fastest path to "working PASE handshake against a real Matter device" is:

```
Phase 2 (framing)  →  Phase 3 (crypto)  →  Phase 4 (session)
                   ↘                    ↘
                     Phase 5 (MRP)        Phase 6 (PASE complete)
                                          ↓
Phase 1 (TLV polish, opportunistically)   Phase 7 (CASE)   ←   Phase 8 (mDNS, parallel)
                                          ↓
                                          Phase 9 (Interaction Model)
                                          ↓
                                          Phase 10 (Data model)
                                          ↓
                                          Phase 11 (CI, tooling, samples)
```

Strict dependency order, single-developer flat list:

1. **§6** — Add `message/` package with Matter Message Header + Payload Header.
2. **§7** — Wire framing into `transport`, change `ReadHandler` signature.
3. **§8** — AES-CCM in `crypto`.
4. **§9** — Real `NextNonce`.
5. **§10** — Real SPAKE2+ context.
6. **§11** — HKDF returning variable-length output.
7. **§12-15** — Session keys, encrypt/decrypt, counter window, unsecured session.
8. **§17-18** — MRP and Exchange Manager.
9. **§19-22** — PASE messages + transcript hash + state machine + sample wiring.
10. **§23** — PASE in-process integration test.
11. **§1-5** — Phase 1 TLV polish (insert here once you've felt the pain points from real protocol work).
12. **§28-30** — mDNS, in parallel with the next steps.
13. **§24-27** — CASE + Fabrics.
14. **§31-36** — Interaction Model.
15. **§37-40** — Data model + persistence + ACL.
16. **§41-45** — CI, lint, integration sample, codegen.

Items §1-5 (TLV polish) are deliberately deferred: the current encoder works for everything in scope through Phase 6, and you'll have a much better sense of which gaps actually matter once you've encoded a few real Matter structs.
