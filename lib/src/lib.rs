//! Contains all HOPR-specific or related Rust types.
//!
//! The individual types are feature-gated.

/// Asynchronous runtime tooling.
#[cfg(feature = "async")]
pub use hopr_async_runtime as async_runtime;

/// Blockchain-related types.
#[cfg(feature = "chain")]
pub use hopr_chain_types as chain;

/// Cryptography-related types.
#[cfg(feature = "crypto")]
pub use hopr_crypto_types as crypto;

/// Types internally used by the HOPR protocol.
#[cfg(feature = "internal")]
pub use hopr_internal_types as internal;

/// Metrics tooling.
#[cfg(feature = "metrics")]
pub use hopr_metrics as metrics;

/// IP networking types for standard protocols such as TCP or UDP.
#[cfg(feature = "network")]
pub use hopr_network_types as network;

/// Tooling for parallel processing (currently via Rayon).
#[cfg(feature = "parallelize")]
pub use hopr_parallelize as parallelize;

/// Basic public types used in the HOPR protocol.
#[cfg(feature = "primitive")]
pub use hopr_primitive_types as primitive;

/// Cryptographically secure random number generation.
#[cfg(feature = "random")]
pub use hopr_crypto_random as crypto_random;
