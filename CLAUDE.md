# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

This is an **early-stage scaffolding/prototype** of a Matter Smart Home Protocol SDK in Go. Most packages outside `tlv/` are skeletons full of `TODO`s — interfaces and types are roughed in, but the actual protocol logic (SPAKE2+, CASE, MRP, AES-CCM, mDNS, Interaction Model parsing) is not implemented yet. When asked to "implement X", first check whether the surrounding scaffolding already commits to a shape you have to honor (e.g. existing struct tags, interface signatures, state enums) before writing new logic.

The project is being developed in an AI-driven workflow with Google DeepMind's Antigravity — expect frequent stub functions, placeholder return values (`return nil, nil`), and `TODO` comments that mark known gaps.

## Common Commands

```bash
# Run all tests (only tlv/ has tests today)
go test ./...

# Run tests in a single package with verbose output
go test -v ./tlv/

# Run a single test by name
go test -v -run TestEncode ./tlv/

# Build everything
go build ./...

# Run the two-process commissioning sample (separate terminals)
go run samples/commissioning/device/main.go        # listens on UDP :5540
go run samples/commissioning/controller/main.go    # talks to 127.0.0.1:5540
```

The module is `go-matter` (no domain prefix), so internal imports look like `import "go-matter/tlv"`. Go 1.20+ is required (go.mod pins 1.25.2).

## Architecture

The SDK is organized as a vertical stack of packages, each owning one layer of the Matter protocol. Dependencies flow strictly downward — never make a lower layer import an upper one.

```
samples/                            executables (device + controller)
   │
   ▼
commissioning/  interaction/        protocol logic (PASE/CASE, Read/Write/Invoke)
   │                │
   ▼                ▼
crypto/         session/  model/    SPAKE2+/HKDF/AES, secure sessions, attribute store
                    │        │
                    ▼        ▼
                transport/ datamodel/   UDP I/O, cluster/endpoint/attribute types
                    │
                    ▼
                  tlv/              Matter binary format (encoder/decoder)
```

Cross-layer wiring is done through small interfaces defined in the *consumer* layer, not the provider:

- `transport.MessageSecurity` — implemented by `session.SessionManager`. Lets `transport` ask "encrypt this payload" without depending on `session`.
- `session.PayloadHandler` — implemented by the application/interaction layer to receive decrypted payloads.
- `interaction.AttributeStore` — implemented by `model.DataStore` to back the Interaction Model with real attribute values.
- `commissioning.CommissioningMessenger` — implemented by sample code (e.g. `ControllerMessenger` in `samples/commissioning/controller/main.go`) to wire the commissioner to a transport.

When adding a new layer or feature, follow this pattern: define the dependency as an interface in the package that *uses* it, then implement that interface in the lower layer with a `var _ Foo = (*Bar)(nil)` compile-time assertion (see `session/session.go:74` and `model/model.go:65`).

## TLV package — the one mature subsystem

`tlv/` is the only package with real test coverage and is the foundation for every Matter wire format in the codebase. Understand it before touching anything that builds messages.

- **Two layers**: `Reader`/`Writer` in `tlv/tlv.go` work with raw `Element` values and tags; `Encoder`/`Decoder` in `tlv/encoder.go`/`tlv/decoder.go` use reflection to (de)serialize Go structs via `tlv:"N"` struct tags.
- **Struct tag format**: `tlv:"<contextID>"` or `tlv:"<contextID>,omitempty"`. The ID is a context-specific tag number (≤255). Fields without a tag, or with `tlv:"-"`, are skipped. See `commissioning.PBKDFParamRequest` (`commissioning/commissioning.go:49`) for a real-world example.
- **Type encoding quirks**:
  - Integer width is auto-selected by value (`PutSignedInt`/`PutUnsignedInt` pick 1/2/4/8 bytes).
  - Booleans encode value-in-type-byte (`0x08` = false, `0x09` = true) — there are no value bytes.
  - `[]byte` becomes a TLV byte string; other slices become `TypeArray` (not `TypeList`).
  - Reflection-based encoding only supports `TagControlContextSpecific` for struct fields. Other tag classes work in the lower-level `Writer` API but not in struct round-tripping.
- **Container reading**: `Reader.ReadElement` reads one element shallowly; for containers, follow up with `Reader.ReadContainerChildren()` to recursively populate `SubElements`. The `Decode` function expects this to have already been done — see the test setup in `tlv/decoder_test.go:62-74`.
- **Known issues to watch for**: the `FullyQualified6`/`FullyQualified8` tag handling in `readTag`/`writeTag` has open TODOs about exact byte layouts; treat anything beyond context-specific tags as untrusted until verified against the Matter spec.

## Commissioning / PASE flow

`commissioning/commissioning.go` defines a state machine (`CommissioningState`) for the PASE handshake but currently only sends `PBKDFParamRequest`. The full message sequence the code is *meant* to implement is documented in `docs/PASE_Explainer.md` — read that file before extending the handshake. Key points:

- `Commissioner` (controller-side initiator) and `Commissionee` (device-side responder) are separate types.
- Both hold a `*crypto.SPAKE2PContext`, which currently wraps the SPAKE2+ state in `interface{}` because the underlying library integration is commented out (`crypto/crypto.go:117`).
- Messages are TLV-encoded structs with context-specific tags 1..N matching the Matter spec field order.
- `Commissionee.HandleMessage` is a stub (`commissioning/commissioning.go:118`) — it will need to dispatch on `c.State` to handle Pake1/Pake2/Pake3.

## Crypto layer caveats

`crypto/crypto.go` has two intentional shortcuts that should *not* ship:

1. `Encrypt`/`Decrypt` use **AES-GCM** as a placeholder — Matter mandates **AES-CCM with a 13-byte nonce**. The `cipher.NewCCM` call is commented out as unavailable in the build env.
2. SPAKE2+ is stubbed to return an empty context; the `jtejido/spake2plus` import is commented out.

When implementing real crypto, replace both and update the `NonceGenerator` to follow the Matter §5.3.1 nonce layout (Security Flags | Session ID | Message Counter | Source Node ID).

## Conventions

- **No `cmd/` directory**: executables live under `samples/<feature>/<role>/main.go`. Follow that layout when adding new runnable demos.
- **TODOs are load-bearing**: `// TODO:` comments mark known protocol gaps, not nice-to-haves. Don't delete them when adding code — update or expand them.
- **Compile-time interface assertions** (`var _ Iface = (*Impl)(nil)`) are used at package boundaries to catch contract drift; preserve them when refactoring implementers.
- **English-only docs/comments**: earlier commits translated docs from German to English (see `git log`). Keep new content in English.
- **Stay on the designated branch**: development happens on feature branches like `claude/add-claude-documentation-*`. Don't push to `main` without explicit instruction.
