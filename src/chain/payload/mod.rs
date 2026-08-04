//! Module defining various Ethereum transaction payload generators for the actions.
//!
//! This module defines the basic `PayloadGenerator` trait that describes how an action
//! is translated into a `TransactionRequest` that can be submitted on-chain.
//!
//! There are two implementations:
//! - `static_based`: the default implementation that uses manual ABI encoding and k256
//!   EIP-1559 signing. It has **no dependency on `hopr-bindings` or alloy** and is always
//!   compiled when the `chain` feature is active (without `use-bindings`).
//! - `bindings_based`: the legacy alloy-backed implementation, compiled only when the
//!   `use-bindings` feature is enabled. Its tests verify correctness of the static
//!   implementation by cross-checking against the alloy-generated payloads.

// Static (no-alloy) implementation — always compiled when chain is enabled so that
// cross-verification tests under `use-bindings` can use both implementations at once.
mod static_based;

// Alloy / hopr-bindings backed implementation. Compiled in production when `use-bindings` is
// active, and always compiled in test mode (hopr-bindings is a dev-dependency).
#[cfg(any(feature = "use-bindings", test))]
mod bindings_based;

// Cross-verification tests that compare full signed transactions from both implementations.
#[cfg(test)]
mod cross_verify;

use crate::crypto::prelude::*;
use crate::internal::prelude::*;
use crate::primitive::prelude::*;

// Re-exports for the static implementation (only when bindings are absent).
#[cfg(not(feature = "use-bindings"))]
pub use static_based::{BasicPayloadGenerator, SafePayloadGenerator, TransactionRequest};

// Re-exports for the bindings-based implementation (legacy / backward compat).
#[cfg(feature = "use-bindings")]
pub(crate) use bindings_based::KeyBindAndAnnouncePayload;
#[cfg(feature = "use-bindings")]
pub use bindings_based::{BasicPayloadGenerator, SafePayloadGenerator, TransactionRequest};

type Result<T> = std::result::Result<T, crate::chain::errors::ChainTypesError>;

/// Estimated gas parameters for a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GasEstimation {
    /// Gas limit for the transaction.
    ///
    /// Defaults to 10 000 000.
    pub gas_limit: u64,
    /// Maximal fee per gas for the transaction.
    ///
    /// Defaults to 10 Gwei
    pub max_fee_per_gas: u128,
    /// Maximal priority fee per gas for the transaction.
    ///
    /// Defaults to 2 Gwei
    pub max_priority_fee_per_gas: u128,
}

impl Default for GasEstimation {
    fn default() -> Self {
        Self {
            gas_limit: 10_000_000,
            max_fee_per_gas: 10_000_000_000,         // 10 Gwei
            max_priority_fee_per_gas: 2_000_000_000, // 2 Gwei
        }
    }
}

/// Trait for transaction payloads that can be signed and encoded to EIP2718 format.
#[async_trait::async_trait]
pub trait SignableTransaction {
    /// Sign the transaction using the given chain keypair and encode it to EIP2718 format.
    async fn sign_and_encode_to_eip2718(
        self,
        nonce: u64,
        chain_id: u64,
        max_gas: Option<GasEstimation>,
        chain_keypair: &ChainKeypair,
    ) -> Result<Box<[u8]>>;
}

/// Trait for various implementations of common on-chain transaction payloads generators.
pub trait PayloadGenerator {
    type TxRequest: SignableTransaction + Send;

    /// Create an ERC20 approve transaction payload. Pre-requisite to open payment channels.
    /// The `spender` address is typically the HOPR Channels contract address.
    fn approve(&self, spender: Address, amount: HoprBalance) -> Result<Self::TxRequest>;

    /// Create a ERC20 transfer transaction payload
    fn transfer<C: Currency>(
        &self,
        destination: Address,
        amount: Balance<C>,
    ) -> Result<Self::TxRequest>;

    /// Creates the transaction payload to announce a node on-chain.
    fn announce(
        &self,
        announcement: AnnouncementData,
        key_binding_fee: HoprBalance,
    ) -> Result<Self::TxRequest>;

    /// Creates the transaction payload to open a payment channel
    fn fund_channel(&self, dest: Address, amount: HoprBalance) -> Result<Self::TxRequest>;

    /// Creates the transaction payload to immediately close an incoming payment channel
    fn close_incoming_channel(&self, source: Address) -> Result<Self::TxRequest>;

    /// Creates the transaction payload that initiates the closure of a payment channel.
    /// Once the notice period is due, the funds can be withdrawn using a
    /// finalizeChannelClosure transaction.
    fn initiate_outgoing_channel_closure(&self, destination: Address) -> Result<Self::TxRequest>;

    /// Creates a transaction payload that withdraws funds from
    /// an outgoing payment channel. This will succeed once the closure
    /// notice period is due.
    fn finalize_outgoing_channel_closure(&self, destination: Address) -> Result<Self::TxRequest>;

    /// Used to create the payload to claim incentives for relaying a mixnet packet.
    fn redeem_ticket(&self, acked_ticket: RedeemableTicket) -> Result<Self::TxRequest>;

    /// Creates a transaction payload to register a Safe instance which is used
    /// to manage the node's funds
    fn register_safe_by_node(&self, safe_addr: Address) -> Result<Self::TxRequest>;

    /// Creates a transaction payload to remove the Safe instance. Once succeeded,
    /// the node no longer manages the funds.
    fn deregister_node_by_safe(&self) -> Result<Self::TxRequest>;

    /// Creates a transaction payload to deploy a new Safe instance with the initial
    /// `balance` transferred from the signer and `admins` as Safe owners.
    ///
    /// If `include_node` is true, the signer will be included in the module after deployment.
    ///
    /// The resulting transaction requires that the signer owns at least the `balance` of wxHOPR tokens. The given
    /// `nonce` must be randomly generated for each deployment.
    fn deploy_safe(
        &self,
        balance: HoprBalance,
        admins: &[Address],
        include_node: bool,
        nonce: [u8; 32],
    ) -> Result<Self::TxRequest>;
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::internal::prelude::*;
    use hex_literal::hex;

    pub const CONTRACT_ADDRS_JSON: &str = r#"{
        "announcements": "0xf1c143B1bA20C7606d56aA2FA94502D25744b982",
        "channels": "0x77C9414043d27fdC98A6A2d73fc77b9b383092a7",
        "module_implementation": "0x32863c4974fBb6253E338a0cb70C382DCeD2eFCb",
        "network_registry": "0x15a315E1320cFF0de84671c0139042EE320CE38d",
        "network_registry_proxy": "0x20559cbD3C2eDcD0b396431226C00D2Cd102eB3F",
        "node_safe_registry": "0x4F7C7dE3BA2B29ED8B2448dF2213cA43f94E45c0",
        "node_safe_migration": "0x222222222222890352Ed9Ca694EdeAC49528D8F3",
        "node_stake_factory": "0x791d190b2c95397F4BcE7bD8032FD67dCEA7a5F2",
        "token": "0xD4fdec44DB9D44B8f2b6d529620f9C0C7066A2c1",
        "ticket_price_oracle": "0x442df1d946303fB088C9377eefdaeA84146DA0A6",
        "winning_probability_oracle": "0xC15675d4CCa538D91a91a8D3EcFBB8499C3B0471",
        "xhopr_token": "0x0000000000000000000000000000000000000000"
    }"#;

    lazy_static::lazy_static! {
        pub static ref REDEEMABLE_TICKET: RedeemableTicket = postcard::from_bytes(&hex!(
            "bea83ba0fcee21da44a30c893f466e6bf0c29bbb0530783365387bffffffffffffff010000000000000000000000000000000000000000014038536c412ff92c3b070d98724a2ac167b7a914aa2151cf71eea3d192b0df195d0184aa92c73bccb27aded5f27fcd1cdcf65889f78cf2e62d2f630f659aa2fba220cba79e6dc2ea1205cb76833c9223cd912f056f3406d73d0d689602afe5e88abc668430def9eacd2b5064acf85d73fb0b351a1c8c20d7f3fa28f0caa757e81226e1ee86a9efdbe7991442286183797296ebaa4d292a2041193a6de59f8f7de35797ed17d90a00f6afefba2daa6391118b76bf99f380e62103d14016cbfa555574e8a5a8fbcb52677dfb7e9267e99c05ebe29603e41b333277208547f752c72aba2a752727be93d7e2f7422230b4e2a9fbd4820318606aff5c9420d12923be051c0212d448103c3d5b5b4196c8d5d369f70fe923f58a7c2cf41100210239d1bc2291826eaed86567d225cf243ebc637275e0a5aedb0d6b1dc82136a38e200000000000000000000000000000000000000000000000000000000000000000"
        )).unwrap();
    }

    // Use this to generate the REDEEMABLE_TICKET variable above.
    // Run with: cargo test -F all-types gen_ticket -- --nocapture --ignored
    // then copy the hex output into the REDEEMABLE_TICKET lazy_static above.
    //
    // NOTE: deliberately outside the lazy_static! block (test fns cannot
    // live inside macro invocations).
    #[test]
    #[ignore]
    fn gen_ticket() -> anyhow::Result<()> {
        use crate::crypto::crypto_traits::Randomizable;
        use crate::crypto::prelude::*;
        use crate::internal::prelude::*;
        use crate::primitive::prelude::*;

        let hk1 = HalfKey::random();
        let hk2 = HalfKey::random();

        let ticket = TicketBuilder::default()
            .counterparty(&ChainKeypair::from_secret(&PRIVATE_KEY_2)?)
            .amount(1000)
            .index(123)
            .channel_epoch(1)
            .eth_challenge(EthereumChallenge::default())
            .build_signed(
                &ChainKeypair::from_secret(&PRIVATE_KEY_1)?,
                &Default::default(),
            )?
            .into_acknowledged(Response::from_half_keys(&hk1, &hk2)?)
            .into_redeemable(
                &&ChainKeypair::from_secret(&PRIVATE_KEY_2)?,
                &Default::default(),
            )?;

        println!("{}", const_hex::encode(postcard::to_allocvec(&ticket)?));
        Ok(())
    }

    pub const PRIVATE_KEY_1: [u8; 32] =
        hex!("c14b8faa0a9b8a5fa4453664996f23a7e7de606d42297d723fc4a794f375e260");
    pub const PRIVATE_KEY_2: [u8; 32] =
        hex!("492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775");
}
