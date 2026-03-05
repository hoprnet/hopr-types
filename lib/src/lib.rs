//! Contains all HOPR-specific or related Rust types.
//!
//! The individual types are feature-gated.

/// Blockchain-related types.
#[cfg(feature = "chain")]
pub use hopr_chain_types as chain;

/// Cryptography-related types.
#[cfg(feature = "crypto")]
pub use hopr_crypto_types as crypto;

/// Types internally used by the HOPR protocol.
#[cfg(feature = "internal")]
pub use hopr_internal_types as internal;

/// Basic public types used in the HOPR protocol.
#[cfg(feature = "primitive")]
pub use hopr_primitive_types as primitive;

/// Cryptographically secure random number generation.
#[cfg(feature = "random")]
pub use hopr_crypto_random as crypto_random;
