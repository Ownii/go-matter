# Messaging Architecture — Commissioning and Operational Share One Stack

This document is the target architecture for how messages flow through go-matter once the operational path is wired up. It exists because the current commissioning code has its own bespoke send/receive shape, and that shape does **not** generalise to subscriptions, MRP retransmission, or multiple concurrent exchanges. Rather than build a second, parallel routing layer for operational traffic, commissioning and operational should converge onto one stack.

Companion reading: [`PASE_Explainer.md`](./PASE_Explainer.md) for the PASE handshake itself, and [`Encryption_Explainer.md`](./Encryption_Explainer.md) for how `Ke` becomes per-direction session keys.

## The realisation

Commissioning and operational look superficially different ("PASE handshake" vs "Read an attribute") but the wire-level mechanics are nearly identical:

- Both ride on `message.Frame` with the same Message Header + Payload Header layout.
- Both use Exchange IDs, Message Counters, and Acks.
- Both rely on MRP for reliable delivery (TODO §17).
- From Pake3 onward, **the rest of commissioning is literally Interaction Model `Invoke` commands** (`ArmFailSafe`, `CSRRequest`, `AddNOC`, `CommissioningComplete`). It is operational traffic, just over a short-lived session.

The only piece that is genuinely special to PASE/CASE is the handshake state machine itself — and even that is "consume frames, run crypto, send frames", which is what every other exchange does too.

## Three session types, one mechanism

There are three session contexts a frame can live in, but they all flow through the same `SessionManager`:

| Phase | Session ID | Encrypted? | Keys |
|---|---|---|---|
| PASE handshake (`PBKDFParamRequest` → `Pake3`) | **0** (unsecured) | No | None — `Ke` doesn't exist yet |
| Post-PASE commissioning (`ArmFailSafe` ... `CommissioningComplete`) | **PASE Secure Session** | Yes | I2R/R2I from HKDF-expanded `Ke` |
| Day-to-day operational (Read/Write/Invoke/Subscribe) | **CASE Secure Session** | Yes | I2R/R2I from CASE transcript + IPK |

Session ID `0` is the only case `SessionManager` needs to special-case: encrypt/decrypt become pass-through. Everything else — including the entire post-Pake3 commissioning flow — goes through real AES-CCM under per-direction keys.

## Target layering

```
   PASE-SM    CASE-SM    InteractionModel       ← protocol layer
       │         │            │                   (state machines & request handlers,
       └─────────┴────────────┘                    each owns its exchange's goroutine)
                 │  *Exchange { Inbox <-chan *Frame; Send(payload) error }
        ┌────────┴──────────┐
        │  ExchangeManager  │   routes inbound frames by ExchangeID;
        │  (+ MRP retx)     │   owns per-exchange goroutines & retx timers
        └────────┬──────────┘
                 │  *Frame (with SessionID; payload encrypted iff SessionID ≠ 0)
        ┌────────┴──────────┐
        │  SessionManager   │   encrypt/decrypt; SessionID == 0 → pass-through;
        │                   │   key install on PASE/CASE completion
        └────────┬──────────┘
                 │  raw bytes
        ┌────────┴──────────┐
        │     Transport     │   UDP I/O; no protocol awareness
        └───────────────────┘
```

Today only the bottom box and a thin sliver of the second-bottom box exist; commissioning bypasses the middle two entirely (it has its own `CommissioningMessenger` interface and is called directly from `transport.Start`'s `ReadHandler` callback). The refactor in this document is to push commissioning *down* through the same plumbing that operational will need.

## What each layer owns

**`transport/`** — bytes ↔ `*message.Frame`. Does not know about sessions, exchanges, MRP, or commissioning. Its single output is "here is a decoded frame from peer X"; its single input is "send this frame to peer X". Today's `ReadHandler` callback becomes "deliver to `SessionManager.OnInbound`".

**`session/`** — encryption boundary. `Encrypt`/`Decrypt` for secured sessions; pass-through for session ID `0`. Owns the session table, key install on handshake completion, counter management, and the replay window. Does not know which exchange a frame belongs to.

**`exchange/`** (new package, per TODO §18) — routing and reliability. Maintains a table of `*Exchange` keyed by `(SessionID, ExchangeID)`. On inbound frame: look up or create the exchange, deliver to its `Inbox` channel. On outbound: stamp the next message counter, store in the MRP retx table, hand to transport. Owns the retx timer goroutine and standalone-Ack generation.

**Protocol handlers** (`commissioning/`, `interaction/`) — state machines that own an `*Exchange`. They consume `<-ex.Inbox` and call `ex.Send(payload)`. They have no knowledge of UDP, encryption, or retransmission.

## Channels at the exchange boundary, methods inside

This unification also resolves the "channels vs callbacks" question:

- **Channels** are right at the exchange-routing layer. `ExchangeManager` runs a goroutine per exchange (needed for MRP timers and `select`-on-inbox-plus-timeout). The handoff from transport-read-loop to per-exchange-goroutine is a `chan *Frame`.
- **Methods / sequential state machines** are right *inside* an exchange. PASE/CASE handshakes are step-by-step request-response code; they look exactly like today's `Commissioner.HandleMessage` switch statement, just driven by `frame := <-ex.Inbox` instead of by a transport callback.

So callbacks aren't replaced wholesale by channels — the two coexist, with channels at the goroutine boundaries that genuinely exist.

## What does NOT unify

These remain distinct, but they sit as policy *on top of* the shared machinery:

1. **Allowed opcodes per session type.** Session 0 only accepts SecureChannel handshake opcodes; PASE-secure sessions accept the commissioning Invoke commands but not arbitrary cluster reads; CASE-secure sessions accept the full Interaction Model catalogue. This is an ACL check applied when dispatching a frame from `ExchangeManager` to a protocol handler.
2. **Session lifetime.** PASE sessions are short-lived (closed at `CommissioningComplete` or when CASE supplants them). CASE sessions persist across restarts and need a fabric-keyed store. Both go through `SessionManager.{Create,Remove}Session` — but the persistence/eviction policy differs.
3. **Fail-safe timer.** `ArmFailSafe` opens a window during commissioning; if it expires before `CommissioningComplete`, the device reverts staged changes. Commissioning-specific state, but it's just a timer next to the protocol handler — no special framing.
4. **The PASE/CASE handshake state machines themselves** stay bespoke. They aren't "Interaction Model" requests, they have their own opcodes and crypto. But they own an `*Exchange` like everything else.

## Migration plan

Order matters — don't refactor commissioning to the new shape before the new shape exists.

1. **Land §11 (variable-length HKDF) and §12-15 (typed session keys, AES-CCM encrypt/decrypt, counter window, unsecured session 0).** Without these, `SessionManager` can't actually encrypt the post-Pake3 frames that the unified path needs to carry.
2. **Land §21 (HKDF `Ke` → I2R/R2I/AttestationChallenge, install in `SessionManager`).** This is the bridge from "PASE handshake on session 0" to "everything else on the PASE-secure session".
3. **Land §17-18 (MRP + `ExchangeManager`).** Define the `Exchange` type. Wire transport → `SessionManager` → `ExchangeManager` → per-exchange goroutine.
4. **Port commissioning to `*Exchange`.** Replace `CommissioningMessenger` with `*Exchange`. The PASE state machine body barely changes: `c.send(frame)` becomes `c.ex.Send(payload)`, and the transport callback becomes a goroutine reading `<-c.ex.Inbox`. Tests stay clean — an in-memory `Exchange` with paired channels replaces today's `loopMessenger`.
5. **Implement post-Pake3 commissioning as regular Interaction Model `Invoke` calls** over the PASE-secure session. No new framing path. This is what Matter actually specifies.
6. **§24-27 (CASE) and §31-36 (Interaction Model) build on the same `*Exchange` abstraction** — no second routing layer.

The cost of doing it in this order is one refactor of `commissioning/` after §17-18. The cost of *not* doing it is two parallel routing/MRP implementations forever.

## Reference for AI agents

When implementing any of TODO §15, §16, §17, §18, §21, §26, §27, §31-36, or refactoring `commissioning/` after `ExchangeManager` exists, treat this document as the architectural contract. In particular:

- Do not add MRP retransmission logic to `transport/` — it belongs on `ExchangeManager`.
- Do not give commissioning its own retransmission, exchange routing, or session table — reuse the shared ones.
- Do not implement post-Pake3 commissioning opcodes (`ArmFailSafe`, `CSRRequest`, `AddNOC`, `CommissioningComplete`) as a bespoke commissioning flow — they are Interaction Model `Invoke` calls.
- Keep `transport/` ignorant of sessions and exchanges; keep `session/` ignorant of exchanges; keep `exchange/` ignorant of protocol semantics.
