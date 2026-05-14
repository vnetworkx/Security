# Design decisions

This file records the main trade-offs behind the security layer.

## 1. Boring validation is a feature
The layer does not try to be clever. It does the same steps in the same order every time.

## 2. Request canonicalization is explicit
The signature must be tied to a stable byte format. The code therefore avoids relying on implicit serialization output.

## 3. Replay defense is separated from durable storage
The fast replay guard is kept separate from the persistent event store. That makes it easier to swap one implementation without disturbing the rest.

## 4. Events are append-only
The event store and audit sink are append-only by design. Historical records are not rewritten by the security layer.

## 5. The engine accepts custom stores
The builder pattern lets you inject different stores without changing the validation pipeline.

## 6. Optional attestations remain optional
The security boundary can accept requests without attestations when policy allows it, but attestations strengthen the result when they exist.

## 7. Protocol versioning is explicit
A version number in the request prevents silent drift in the canonical format.

## 8. Separate data from policy
The request types describe what was asked for. The policy engine describes whether it is allowed.

## 9. Fail closed
Any invalid or missing condition leads to rejection rather than approximation.
