//! Contains all HOPR-specific or related Rust types.
#![doc = include_str!("../README.md")]

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

/// Blockchain-related types.
#[cfg(feature = "chain")]
pub mod chain;

/// Key pair management and Ethereum keystore support.
#[cfg(feature = "keypair")]
pub mod keypair;

/// OpenTelemetry-backed metrics collection.
#[cfg(feature = "telemetry")]
pub mod telemetry;
