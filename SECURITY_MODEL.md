# Security model

This document explains the trust boundary implemented by the Vector Security Layer.

## Purpose

The security layer exists to ensure that requests entering the Vector Network are:

- authenticated
- integrity-protected
- replay-safe
- policy-compliant
- auditable
- deterministic to validate

It is a gatekeeper, not a ledger, and not the authoritative state machine.

## Threat model

The layer is expected to defend against:

- forged requests
- signature tampering
- request replay
- wallet and region spoofing
- oversized payloads
- malformed request structures
- stale or out-of-policy timestamps
- weak or missing attestations
- accidental duplicate submissions
- corrupted transport data
- unauthorized cross-region actions
- stale protocol versions
- replay pressure after a restart

It is not meant to solve every system problem by itself. It should be combined with a kernel, storage layer, and node synchronization layer that preserve the same invariants.

## Security invariants

1. Every accepted request must be signed by the correct key.
2. Every accepted request must be bound to the correct wallet.
3. Every accepted request must be bound to the correct region unless policy says otherwise.
4. No replayed nonce may be accepted twice.
5. No replayed event hash may be admitted as new work.
6. No request may bypass policy validation.
7. No audit event may be emitted without a validated request.
8. No private key material may be stored in shared network state.
9. No nondeterministic validation step should affect acceptance.
10. No trusted live state should be treated as the source of truth.
11. No unsupported protocol version should silently degrade into best-effort mode.
12. No canonicalization rule should depend on local machine layout or JSON formatting quirks.

## Request lifecycle

A request moves through the following stages:

### 1. Structural validation
The request is checked for empty identifiers, malformed context, invalid protocol version, and obviously invalid inputs.

### 2. Policy validation
The policy engine enforces payload size, operation permission, cross-region constraints, timestamp drift, and minimum auth ratio.

### 3. Attestation validation
The optional attestation bundle is checked for subject binding and aggregate score.

### 4. Replay validation
The nonce is checked against the replay guard before acceptance.

### 5. Signature validation
The request bytes are canonicalized and verified against the supplied public key.

### 6. Event construction
A deterministic event record is created for the accepted request.

### 7. Event and audit emission
The event is written to the event store and appended to the audit sink.

### 8. Replay commitment
The nonce and event hash are remembered only after the request has been accepted and recorded.

## Canonicalization

The security boundary uses canonical byte construction for request signing and event fingerprinting. This is necessary because a signature must be stable across machines, runtimes, and serialization layers.

The canonical form should remain stable over time. Any future change to the encoding must be versioned so that older nodes can still verify older requests.

## Replay protection

The in-memory replay guard tracks nonces and event hashes. It is intentionally bounded so that it does not grow without limit.

For production deployment, a persistent replay store should be added so the system can survive restarts without losing replay history.

Recommended extensions:

- write replay entries to disk or a database
- expire entries with a deterministic retention policy
- replicate replay state across nodes in a bounded format
- checkpoint replay state as part of node snapshots

## Attestations

Attestations are treated as supplemental trust signals, not as a replacement for signature verification.

The current model assumes that attestations:
- belong to the same wallet subject
- are scored in the range 0.0 to 1.0
- are aggregated into a deterministic mean score

This is deliberately simple. In a real deployment, the score calculation may incorporate issuer reputation, time decay, slashing history, validator quorum, or business-specific compliance signals.

## Audit model

Audit records are append-only at the API boundary. The in-memory log is provided as a default sink for development and tests.

Production deployments should replace or augment this with:
- file-backed append-only logs
- object storage
- database-backed archives
- tamper-evident log chains
- signed checkpoints
- chain heads for cross-node comparison

## Extension points

Future versions of the security layer can add:

- persistent replay stores
- policy DSLs
- hardware attestation
- node identity and mTLS
- rate limiting
- request quotas
- distributed audit fanout
- policy versioning
- signature scheme agility
- multi-key wallet support
- configurable event retention
- trust scoring for attestations and issuers
- richer rejection telemetry

## Operational guidance

Before rollout, run:
- unit tests
- integration tests
- signature and canonicalization tests
- replay tests
- fuzz tests against request parsing and serialization
- CI linting with formatting and clippy checks

The security boundary should fail closed. If a check is uncertain, missing, or malformed, the request should be rejected rather than approximated.
