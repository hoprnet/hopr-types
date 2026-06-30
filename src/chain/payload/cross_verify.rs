//! Cross-verification tests that compare the full signed EIP-1559 transaction bytes produced by
//! the alloy-backed `bindings_based` implementation against those produced by the manual
//! `static_based` implementation.
//!
//! Both generators receive identical inputs (keys, nonce, chain-id, contract addresses) and the
//! resulting byte sequences must be identical.  Any divergence in ABI encoding, RLP framing, or
//! k256 signing will be caught here.
//!
//! These tests are compiled only when the `use-bindings` feature is active (which also enables
//! `static_based` compilation so both are available simultaneously).

use hex_literal::hex;
use multiaddr::Multiaddr;
use std::str::FromStr;

use crate::chain::payload::{
    PayloadGenerator, SignableTransaction,
    bindings_based,
    static_based,
    tests::CONTRACT_ADDRS,
};
use crate::crypto::prelude::*;
use crate::internal::prelude::*;
use crate::primitive::prelude::*;

const PRIVATE_KEY_1: [u8; 32] =
    hex!("c14b8faa0a9b8a5fa4453664996f23a7e7de606d42297d723fc4a794f375e260");
const PRIVATE_KEY_2: [u8; 32] =
    hex!("492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775");

lazy_static::lazy_static! {
    static ref REDEEMABLE_TICKET: RedeemableTicket = postcard::from_bytes(&hex!(
        "bea83ba0fcee21da44a30c893f466e6bf0c29bbb0530783365387bffffffffffffff010000000000000000000000000000000000000000014038536c412ff92c3b070d98724a2ac167b7a914aa2151cf71eea3d192b0df195d0184aa92c73bccb27aded5f27fcd1cdcf65889f78cf2e62d2f630f659aa2fba220cba79e6dc2ea1205cb76833c9223cd912f056f3406d73d0d689602afe5e88abc668430def9eacd2b5064acf85d73fb0b351a1c8c20d7f3fa28f0caa757e81226e1ee86a9efdbe7991442286183797296ebaa4d292a2005a089ed04b7dbb28ad1c9074f13d10115b0002ca88f4d68ce14549099773c192103d14016cbfa555574e8a5a8fbcb52677dfb7e9267e99c05ebe29603e41b33327705ddecfc569b0125d1ae9a3d3cb637a3c8c9eaafe90e6a1877292227065fbdcc897e95962ce1604fb644782e9029a046650ed84c4f1043b753959d7819f53cec200000000000000000000000000000000000000000000000000000000000000000"
    )).unwrap();
}

/// Signs `tx` (bindings-based) and `tx_static` (static-based) with the same parameters and
/// asserts the raw EIP-2718 bytes are identical.
macro_rules! assert_signed_eq {
    ($label:expr, $tx_bindings:expr, $tx_static:expr, $nonce:expr, $chain_id:expr, $key:expr) => {{
        let bindings_bytes = $tx_bindings
            .sign_and_encode_to_eip2718($nonce, $chain_id, None, $key)
            .await
            .expect(concat!($label, ": bindings sign failed"));
        let static_bytes = $tx_static
            .sign_and_encode_to_eip2718($nonce, $chain_id, None, $key)
            .await
            .expect(concat!($label, ": static sign failed"));
        assert_eq!(
            bindings_bytes,
            static_bytes,
            "{}: signed transaction mismatch\n  bindings: {}\n  static  : {}",
            $label,
            hex::encode(&*bindings_bytes),
            hex::encode(&*static_bytes),
        );
    }};
}

#[tokio::test]
async fn cross_verify_announce_basic() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let kb = KeyBinding::new(
        (&key).into(),
        &OffchainKeypair::from_secret(&PRIVATE_KEY_1)?,
    );
    let ma = Multiaddr::from_str("/ip4/1.2.3.4/tcp/56")?;
    let ad = AnnouncementData::new(kb, Some(ma))?;

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);

    let tx_b = b_gen.announce(ad.clone(), 100_u32.into())?;
    let tx_s = s_gen.announce(ad, 100_u32.into())?;

    assert_signed_eq!("announce_basic", tx_b, tx_s, 2, 1, &key);
    Ok(())
}

#[tokio::test]
async fn cross_verify_announce_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let module: Address = [1u8; Address::SIZE].into();
    let kb = KeyBinding::new(
        (&key).into(),
        &OffchainKeypair::from_secret(&PRIVATE_KEY_1)?,
    );
    let ma = Multiaddr::from_str("/ip4/5.6.7.8/tcp/99")?;
    let ad = AnnouncementData::new(kb, Some(ma))?;

    let b_gen = bindings_based::SafePayloadGenerator::new(&key, *CONTRACT_ADDRS, module);
    let s_gen = static_based::SafePayloadGenerator::new(&key, *CONTRACT_ADDRS, module);

    let tx_b = b_gen.announce(ad.clone(), 0_u32.into())?;
    let tx_s = s_gen.announce(ad, 0_u32.into())?;

    assert_signed_eq!("announce_safe", tx_b, tx_s, 1, 1, &key);
    Ok(())
}

#[tokio::test]
async fn cross_verify_redeem_ticket_basic() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;
    let ticket = *REDEEMABLE_TICKET;

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);

    let tx_b = b_gen.redeem_ticket(ticket)?;
    let tx_s = s_gen.redeem_ticket(ticket)?;

    assert_signed_eq!("redeem_ticket_basic", tx_b, tx_s, 1, 1, &key);
    Ok(())
}

#[tokio::test]
async fn cross_verify_redeem_ticket_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;
    let module: Address = [1u8; Address::SIZE].into();
    let ticket = *REDEEMABLE_TICKET;

    let b_gen = bindings_based::SafePayloadGenerator::new(&key, *CONTRACT_ADDRS, module);
    let s_gen = static_based::SafePayloadGenerator::new(&key, *CONTRACT_ADDRS, module);

    let tx_b = b_gen.redeem_ticket(ticket)?;
    let tx_s = s_gen.redeem_ticket(ticket)?;

    assert_signed_eq!("redeem_ticket_safe", tx_b, tx_s, 2, 1, &key);
    Ok(())
}

#[tokio::test]
async fn cross_verify_withdraw_basic() -> anyhow::Result<()> {
    let key_alice = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let key_bob = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key_alice).into(), *CONTRACT_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key_alice).into(), *CONTRACT_ADDRS);

    let tx_b = b_gen.transfer((&key_bob).into(), HoprBalance::from(100))?;
    let tx_s = s_gen.transfer((&key_bob).into(), HoprBalance::from(100))?;

    assert_signed_eq!("withdraw_basic", tx_b, tx_s, 1, 1, &key_bob);
    Ok(())
}

#[tokio::test]
async fn cross_verify_withdraw_safe() -> anyhow::Result<()> {
    let key_alice = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let key_bob = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;
    let module: Address = [1u8; Address::SIZE].into();

    let b_gen = bindings_based::SafePayloadGenerator::new(&key_alice, *CONTRACT_ADDRS, module);
    let s_gen = static_based::SafePayloadGenerator::new(&key_alice, *CONTRACT_ADDRS, module);

    let tx_b = b_gen.transfer((&key_bob).into(), HoprBalance::from(100))?;
    let tx_s = s_gen.transfer((&key_bob).into(), HoprBalance::from(100))?;

    assert_signed_eq!("withdraw_safe", tx_b, tx_s, 2, 1, &key_bob);
    Ok(())
}

#[tokio::test]
async fn cross_verify_fund_channel() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let dest: Address = [0xab; Address::SIZE].into();

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);

    let tx_b = b_gen.fund_channel(dest, HoprBalance::from(1000))?;
    let tx_s = s_gen.fund_channel(dest, HoprBalance::from(1000))?;

    assert_signed_eq!("fund_channel", tx_b, tx_s, 5, 1, &key);
    Ok(())
}

#[tokio::test]
async fn cross_verify_fund_channel_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let module: Address = [1u8; Address::SIZE].into();
    let dest: Address = [0xab; Address::SIZE].into();

    let b_gen = bindings_based::SafePayloadGenerator::new(&key, *CONTRACT_ADDRS, module);
    let s_gen = static_based::SafePayloadGenerator::new(&key, *CONTRACT_ADDRS, module);

    let tx_b = b_gen.fund_channel(dest, HoprBalance::from(1000))?;
    let tx_s = s_gen.fund_channel(dest, HoprBalance::from(1000))?;

    assert_signed_eq!("fund_channel_safe", tx_b, tx_s, 5, 1, &key);
    Ok(())
}

#[tokio::test]
async fn cross_verify_close_incoming_channel() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let source: Address = [0xcd; Address::SIZE].into();

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);

    let tx_b = b_gen.close_incoming_channel(source)?;
    let tx_s = s_gen.close_incoming_channel(source)?;

    assert_signed_eq!("close_incoming_channel", tx_b, tx_s, 3, 1, &key);
    Ok(())
}

#[tokio::test]
async fn cross_verify_initiate_outgoing_channel_closure() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let dest: Address = [0xef; Address::SIZE].into();

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);

    let tx_b = b_gen.initiate_outgoing_channel_closure(dest)?;
    let tx_s = s_gen.initiate_outgoing_channel_closure(dest)?;

    assert_signed_eq!("initiate_outgoing_closure", tx_b, tx_s, 4, 1, &key);
    Ok(())
}

#[tokio::test]
async fn cross_verify_finalize_outgoing_channel_closure() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let dest: Address = [0xef; Address::SIZE].into();

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);

    let tx_b = b_gen.finalize_outgoing_channel_closure(dest)?;
    let tx_s = s_gen.finalize_outgoing_channel_closure(dest)?;

    assert_signed_eq!("finalize_outgoing_closure", tx_b, tx_s, 4, 1, &key);
    Ok(())
}

#[tokio::test]
async fn cross_verify_register_safe_by_node() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let safe: Address = [0x55; Address::SIZE].into();

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *CONTRACT_ADDRS);

    let tx_b = b_gen.register_safe_by_node(safe)?;
    let tx_s = s_gen.register_safe_by_node(safe)?;

    assert_signed_eq!("register_safe_by_node", tx_b, tx_s, 7, 1, &key);
    Ok(())
}

#[tokio::test]
async fn cross_verify_deregister_node_by_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let module: Address = [1u8; Address::SIZE].into();

    let b_gen = bindings_based::SafePayloadGenerator::new(&key, *CONTRACT_ADDRS, module);
    let s_gen = static_based::SafePayloadGenerator::new(&key, *CONTRACT_ADDRS, module);

    let tx_b = b_gen.deregister_node_by_safe()?;
    let tx_s = s_gen.deregister_node_by_safe()?;

    assert_signed_eq!("deregister_node_by_safe", tx_b, tx_s, 8, 1, &key);
    Ok(())
}
