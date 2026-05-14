# Architecture overview

The Vector Security Layer is the front door of the Vector Network.

It exists to convert an incoming request into a deterministic decision:

- accept and record
- reject with a concrete reason

That decision must be explainable, reproducible, and independent of the local machine as much as possible.

## Layer responsibilities

### 1. Request intake
The crate receives a request envelope containing:
- identity context
- operation metadata
- payload bytes
- parent hashes
- signature
- attestations

### 2. Structural validation
The request is checked for empty fields, version mismatches, invalid timestamps, and malformed identifiers.

### 3. Policy enforcement
The policy layer rejects unsupported operations, oversized payloads, disallowed cross-region work, and requests below the auth threshold.

### 4. Cryptographic verification
The request is canonicalized and verified with Ed25519.

### 5. Attestation aggregation
Optional attestations are checked against the wallet subject and reduced into a deterministic score.

### 6. Replay defense
The replay layer rejects duplicate nonces and duplicate event hashes.

### 7. Event materialization
A normalized event is created. It includes hashes, scores, state labels, and the signature that bound the request.

### 8. Durable recording
The event is written to a store and appended to the audit sink.

### 9. Kernel handoff
The next layer receives a validated, recorded event rather than an untrusted request.

## Why the module split matters

The modules are intentionally small because security systems get harder to trust as they get harder to reason about. Each module focuses on one part of the trust boundary:

- `types` defines the data model
- `crypto` defines the byte-level and signature rules
- `policy` defines acceptance constraints
- `attestation` defines supplemental trust signals
- `replay` defines fast local replay defense
- `storage` defines persistence interfaces
- `audit` defines append-only visibility
- `engine` wires the components together

## Design choice: deterministic first, convenient second

A validation layer should prioritize stability over convenience. The code favors:

- explicit fields
- fixed signing rules
- predictable hashing
- clear errors
- conservative defaults

That makes it easier to reason about upgrades and easier to detect deviations.

## Design choice: the event is more important than the request

The request is an input. The event is the record of what the system decided.

That is why the engine writes the event only after all checks succeed. The record should be the artifact that downstream systems trust.
