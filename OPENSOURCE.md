# Open-source links used in this folder

Official project documentation for the Rust crates used here:

- ed25519-dalek — signing and verification
  - https://docs.rs/ed25519-dalek/latest/ed25519_dalek/
- BLAKE3 — hashing and domain separation helpers
  - https://docs.rs/blake3/latest/blake3/
- Serde — serialization and deserialization
  - https://docs.rs/serde/latest/serde/
- serde_json — JSON persistence for the example file store
  - https://docs.rs/serde_json/latest/serde_json/
- Tokio — async runtime and task integration
  - https://docs.rs/tokio/latest/tokio/
- thiserror — ergonomic error definitions
  - https://docs.rs/thiserror/latest/thiserror/
- anyhow — application-level error handling
  - https://docs.rs/anyhow/latest/anyhow/
- tracing — structured logging
  - https://docs.rs/tracing/latest/tracing/
- tracing-subscriber — log subscriber for demos and local runs
  - https://docs.rs/tracing-subscriber/latest/tracing_subscriber/
- rand_core — secure random-number traits
  - https://docs.rs/rand_core/latest/rand_core/

Repository pages for upstream open-source projects:

- ed25519-dalek
  - https://github.com/dalek-cryptography/ed25519-dalek
- BLAKE3
  - https://github.com/BLAKE3-team/BLAKE3
- Serde
  - https://github.com/serde-rs/serde
- Tokio
  - https://github.com/tokio-rs/tokio
- thiserror
  - https://github.com/dtolnay/thiserror
- tracing
  - https://github.com/tokio-rs/tracing
- serde_json
  - https://github.com/serde-rs/json
- anyhow
  - https://github.com/dtolnay/anyhow

Optional open-source projects to consider for future expansion:

- parking_lot — faster synchronization primitives
  - https://github.com/Amanieu/parking_lot
- dashmap — concurrent hash map
  - https://github.com/xacrimon/dashmap
- tempfile — safe temporary file utilities
  - https://github.com/Stebalien/tempfile
- uuid — typed UUID generation
  - https://github.com/uuid-rs/uuid
- clap — command-line interfaces
  - https://github.com/clap-rs/clap
- criterion — benchmarking harness
  - https://github.com/bheisler/criterion.rs
- proptest — property-based testing
  - https://github.com/proptest-rs/proptest
- opentelemetry — observability instrumentation
  - https://github.com/open-telemetry/opentelemetry-rust
- prometheus — metrics export
  - https://github.com/tikv/rust-prometheus
- indexmap — deterministic hash map ordering
  - https://github.com/indexmap-rs/indexmap

These optional dependencies are not required by the current package, but they are useful candidates when the security layer grows into a larger service.
