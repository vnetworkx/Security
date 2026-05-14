# Deployment notes

This folder is a reference security boundary for the Vector Network. It is intentionally conservative, easy to inspect, and narrow in scope.

## What is improved here

- protocol-version enforcement
- stronger structural validation
- clearer policy boundaries
- bounded replay tracking
- file-backed replay store reference implementation
- append-only event store reference implementation
- richer event fields for hashing, scoring, and auditability
- builder-based store injection for integration work
- more detailed operator documentation

## What still belongs in adjacent layers

This crate should not become the kernel, the consensus engine, or the wallet itself. Those layers belong elsewhere.

You still need:

- a deterministic kernel
- a durable event store strategy
- a snapshot strategy
- a node-sync protocol
- a transport security layer
- rate limiting and abuse controls
- a wallet client with secure key handling
- an observability pipeline
- upgrade and migration procedures

## Safe integration pattern

A good integration pattern is:

1. Receive a request at the edge.
2. Validate it in this security layer.
3. Write the resulting event to the durable event store.
4. Forward the validated work to the deterministic kernel.
5. Persist or replicate the kernel result separately.

The security layer should never be the only source of truth.

## Additional hardening suggestions

- move file-backed stores onto a database or durable object store
- replace local replay state with a replicated cache or snapshot
- sign checkpoints and restore points
- add explicit rate-limiting per wallet, region, and peer
- run property tests over the canonical encoding helpers
- run fuzzing on request serialization and deserialization
- capture rejection metrics and export them to your observability stack
- define a protocol upgrade policy before multiple versions exist in the wild

## Maintenance posture

The package is structured to be easy to review. Small modules reduce audit complexity and make it easier to reason about what happens before a state transition is approved.
