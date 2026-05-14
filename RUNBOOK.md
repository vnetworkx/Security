# Operator runbook

This document describes how to use the security layer in a service boundary.

## Startup checklist

- Confirm the configured protocol version.
- Confirm the policy envelope matches the deployment region.
- Confirm the replay store is empty or restored from a trusted snapshot.
- Confirm the event store is writable.
- Confirm signing keys are only present in the client or wallet boundary.
- Confirm logs and metrics are enabled.

## Acceptance workflow

1. Receive a request envelope.
2. Validate the request with the security engine.
3. Persist the resulting event.
4. Forward the event to the kernel or downstream processor.
5. Emit audit and metrics signals.

## Common rejection reasons

- replay detected
- wallet mismatch
- region mismatch
- unsupported protocol version
- payload too large
- signature invalid
- auth ratio below threshold
- attestation score below threshold
- timestamp drift too large
- disallowed operation

## Operational advice

- Keep the replay cache large enough to cover your expected request burst.
- Use a persistent replay store if restarts are frequent.
- Track rejection reasons over time; sudden shifts often indicate an integration problem or an attack.
- Treat repeated signature failures as a signal of client-side corruption or active probing.
- Add alerting for spikes in replay detection or cross-region rejection.

## Upgrade approach

When the protocol evolves:

- add a version rather than mutating existing canonical rules silently
- preserve verification of older requests as long as they remain supported
- keep the event format stable across the version boundary whenever possible
- test replay and signature compatibility before rollout
