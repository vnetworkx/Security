# Vector Security Layer

This repository contains the security-layer boundary for the Vector Network. It is designed as a Rust crate that sits in front of the kernel and performs the checks that should happen before any durable state transition is allowed to proceed.

The goal is not to replace the kernel, storage engine, or consensus layer. The goal is to enforce the trust boundary:

- bind a request to a wallet and public key
- verify the request signature
- reject replays
- enforce policy constraints
- score attestations
- emit immutable audit records
- hand only validated work to the next layer

The implementation is intentionally conservative. The crate favors deterministic canonicalization, explicit validation, and small modules that are easy to test, audit, and replace.

## What is included

- Ed25519 request signing and signature verification
- BLAKE3 hashing for request and event fingerprints
- canonical byte encoding helpers for stable signing
- replay protection with bounded in-memory retention
- policy enforcement for payload size, auth thresholds, timestamp drift, cross-region controls, and protocol versioning
- attestation scoring and subject binding checks
- append-only audit logging
- optional file-backed event and replay storage helpers
- async validation entrypoint for service integration
- a builder API for custom store wiring
- unit tests and a runnable demo example

## Repository layout

- `src/types.rs` — core request, event, policy, and identity types
- `src/crypto.rs` — hashing, signing, verification, and canonical serialization helpers
- `src/policy.rs` — policy rules and request validation
- `src/replay.rs` — in-memory replay guard for fast local protection
- `src/attestation.rs` — attestation scoring and threshold checks
- `src/audit.rs` — append-only in-memory audit sink
- `src/storage.rs` — storage traits and reference implementations
- `src/engine.rs` — the high-level security pipeline and builder
- `src/config.rs` — service configuration structure
- `examples/demo.rs` — runnable example
- `tests/security_layer.rs` — integration-style tests

## Security model in practice

A request is accepted only when the following conditions all hold:

1. The request is structurally valid.
2. The wallet in the request matches the wallet in the trusted context.
3. The region in the request matches the region in the trusted context, unless policy explicitly allows cross-region requests.
4. The protocol version is supported.
5. The request is not a replayed nonce.
6. The request signature validates against the verified public key.
7. The payload size remains within configured limits.
8. The timestamp drift is within allowed bounds.
9. The auth ratio clears the configured threshold.
10. Any supplied attestations pass subject binding and scoring checks.
11. A deterministic event can be constructed and recorded.

Those checks are meant to be boring. In a security boundary, boring is good.

## Running the crate

```bash
cargo build
cargo test
cargo run --example demo
```

## Suggested production usage

In a full Vector Network deployment, this crate should typically be used as a service boundary in front of:

- a deterministic kernel
- an immutable event store
- a node synchronization layer
- a contract execution runtime
- a policy service
- a wallet or signing client

The security layer should never be the only source of truth. It should be the first gate that prevents malformed or malicious input from reaching the rest of the system.

## Open-source dependencies

This crate is built from widely used open-source Rust components. The links in `OPEN_SOURCE_LINKS.md` point to official documentation and upstream repositories.

## Notes on hardening

For a real deployment, consider adding:

- persistent replay storage
- disk-backed audit sinks
- configuration file loading
- request quotas and rate limiting
- fuzz testing for canonical encoding and request parsing
- signed config distribution
- metrics export
- integration with node identity and transport security
- independent review of the canonical byte format
- signature-scheme agility planning
- operational dashboards for replay pressure and rejection reasons

The current folder is intentionally compact, but the structure is arranged so those upgrades can be added without rewriting the core API.

## What changed in this version

This version expands the security boundary into a broader reference package:

- stronger protocol-version checks
- stricter request and signature validation
- a builder for custom replay, audit, and event stores
- a file-backed replay store reference implementation
- richer event fields for request hashes, attestation scoring, and drain accounting
- a fuller set of docs for operators and maintainers

The package is still intentionally dependency-light. The value is in the structure, not in a large dependency graph.
