//! Network- and session-related types shared across the HOPR stack.
//!
//! Runtime-specific behavior (e.g. DNS resolution, socket helpers) lives in the
//! `hopr-utilities` crate; this module only hosts the plain data types.

/// Errors thrown by the network types.
pub mod errors;

/// HOPR Session and session-target types.
pub mod session;

/// Network host/address types.
pub mod types;

pub use errors::NetworkTypeError;
pub use session::*;
pub use types::*;
