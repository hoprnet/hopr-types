//! Contains all HOPR-specific or related Rust types.
#![doc = include_str!("../README.md")]
// clippy 1.99's `double_must_use` fires on `async-trait`-generated methods: the macro emits a
// `#[must_use]` function returning an already-`#[must_use]` boxed `Future`. The attribute lives in
// the expansion, so it can't be removed at the source. Allow it until async-trait or clippy drops
// the redundant flag.
#![allow(clippy::double_must_use)]

/// Basic public types used in the HOPR protocol.
#[cfg(feature = "primitive")]
pub mod primitive;

/// Cryptographically secure random number generation.
#[cfg(feature = "random")]
pub mod crypto_random;

/// Cryptography-related types.
#[cfg(feature = "crypto")]
pub mod crypto;

/// Types internally used by the HOPR protocol.
#[cfg(feature = "internal")]
pub mod internal;

/// Network- and session-related types (hosts, sealed targets, session identifiers).
#[cfg(feature = "network")]
pub mod network;

/// Blockchain-related types.
#[cfg(feature = "chain")]
pub mod chain;

/// Key pair management and Ethereum keystore support.
#[cfg(feature = "keypair")]
pub mod keypair;

/// OpenTelemetry-backed metrics collection.
#[cfg(feature = "telemetry")]
pub mod telemetry;
