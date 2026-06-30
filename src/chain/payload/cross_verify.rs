//! Cross-verification tests comparing the full signed EIP-1559 bytes produced by the
//! alloy-backed `bindings_based` implementation against the manual `static_based` one.
//!
//! These tests run unconditionally: `hopr-bindings` is a dev-dependency so both
//! implementations are always compiled during `cargo test`, regardless of whether the
//! `use-bindings` production feature is active.

#![cfg(test)]

use multiaddr::Multiaddr;
use std::str::FromStr;

use crate::chain::payload::tests::{CONTRACT_ADDRS_JSON, PRIVATE_KEY_1, PRIVATE_KEY_2, REDEEMABLE_TICKET};
use crate::chain::payload::{PayloadGenerator, SignableTransaction, bindings_based, static_based};
use crate::crypto::prelude::*;
use crate::internal::prelude::*;
use crate::primitive::prelude::*;

lazy_static::lazy_static! {
    // bindings_based always uses hopr_bindings::ContractAddresses (available as dev-dep).
    static ref B_ADDRS: hopr_bindings::ContractAddresses = serde_json::from_str(CONTRACT_ADDRS_JSON).unwrap();
    // static_based uses crate::chain::ContractAddresses (local struct when not use-bindings).
    static ref S_ADDRS: crate::chain::ContractAddresses = serde_json::from_str(CONTRACT_ADDRS_JSON).unwrap();
}

macro_rules! assert_signed_eq {
    ($label:expr, $tx_b:expr, $tx_s:expr, $nonce:expr, $chain_id:expr, $key:expr) => {{
        let b = $tx_b
            .sign_and_encode_to_eip2718($nonce, $chain_id, None, $key)
            .await
            .expect(concat!($label, ": bindings sign failed"));
        let s = $tx_s
            .sign_and_encode_to_eip2718($nonce, $chain_id, None, $key)
            .await
            .expect(concat!($label, ": static sign failed"));
        assert_eq!(
            b,
            s,
            "{}: signed transaction mismatch\n  bindings: {}\n  static  : {}",
            $label,
            hex::encode(&*b),
            hex::encode(&*s),
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

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *B_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *S_ADDRS);

    assert_signed_eq!(
        "announce_basic",
        b_gen.announce(ad.clone(), 100_u32.into())?,
        s_gen.announce(ad, 100_u32.into())?,
        2,
        1,
        &key
    );
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

    let b_gen = bindings_based::SafePayloadGenerator::new(&key, *B_ADDRS, module);
    let s_gen = static_based::SafePayloadGenerator::new(&key, *S_ADDRS, module);

    assert_signed_eq!(
        "announce_safe",
        b_gen.announce(ad.clone(), 0_u32.into())?,
        s_gen.announce(ad, 0_u32.into())?,
        1,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn cross_verify_redeem_ticket_basic() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;
    let ticket = *REDEEMABLE_TICKET;

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *B_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *S_ADDRS);

    assert_signed_eq!(
        "redeem_ticket_basic",
        b_gen.redeem_ticket(ticket)?,
        s_gen.redeem_ticket(ticket)?,
        1,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn cross_verify_redeem_ticket_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;
    let module: Address = [1u8; Address::SIZE].into();
    let ticket = *REDEEMABLE_TICKET;

    let b_gen = bindings_based::SafePayloadGenerator::new(&key, *B_ADDRS, module);
    let s_gen = static_based::SafePayloadGenerator::new(&key, *S_ADDRS, module);

    assert_signed_eq!(
        "redeem_ticket_safe",
        b_gen.redeem_ticket(ticket)?,
        s_gen.redeem_ticket(ticket)?,
        2,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn cross_verify_withdraw_basic() -> anyhow::Result<()> {
    let key_alice = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let key_bob = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key_alice).into(), *B_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key_alice).into(), *S_ADDRS);

    assert_signed_eq!(
        "withdraw_basic",
        b_gen.transfer((&key_bob).into(), HoprBalance::from(100))?,
        s_gen.transfer((&key_bob).into(), HoprBalance::from(100))?,
        1,
        1,
        &key_bob
    );
    Ok(())
}

#[tokio::test]
async fn cross_verify_withdraw_safe() -> anyhow::Result<()> {
    let key_alice = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let key_bob = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;
    let module: Address = [1u8; Address::SIZE].into();

    let b_gen = bindings_based::SafePayloadGenerator::new(&key_alice, *B_ADDRS, module);
    let s_gen = static_based::SafePayloadGenerator::new(&key_alice, *S_ADDRS, module);

    assert_signed_eq!(
        "withdraw_safe",
        b_gen.transfer((&key_bob).into(), HoprBalance::from(100))?,
        s_gen.transfer((&key_bob).into(), HoprBalance::from(100))?,
        2,
        1,
        &key_bob
    );
    Ok(())
}

#[tokio::test]
async fn cross_verify_fund_channel() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let dest: Address = [0xab; Address::SIZE].into();

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *B_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *S_ADDRS);

    assert_signed_eq!(
        "fund_channel",
        b_gen.fund_channel(dest, HoprBalance::from(1000))?,
        s_gen.fund_channel(dest, HoprBalance::from(1000))?,
        5,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn cross_verify_fund_channel_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let module: Address = [1u8; Address::SIZE].into();
    let dest: Address = [0xab; Address::SIZE].into();

    let b_gen = bindings_based::SafePayloadGenerator::new(&key, *B_ADDRS, module);
    let s_gen = static_based::SafePayloadGenerator::new(&key, *S_ADDRS, module);

    assert_signed_eq!(
        "fund_channel_safe",
        b_gen.fund_channel(dest, HoprBalance::from(1000))?,
        s_gen.fund_channel(dest, HoprBalance::from(1000))?,
        5,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn cross_verify_close_incoming_channel() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let source: Address = [0xcd; Address::SIZE].into();

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *B_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *S_ADDRS);

    assert_signed_eq!(
        "close_incoming",
        b_gen.close_incoming_channel(source)?,
        s_gen.close_incoming_channel(source)?,
        3,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn cross_verify_initiate_outgoing_channel_closure() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let dest: Address = [0xef; Address::SIZE].into();

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *B_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *S_ADDRS);

    assert_signed_eq!(
        "initiate_closure",
        b_gen.initiate_outgoing_channel_closure(dest)?,
        s_gen.initiate_outgoing_channel_closure(dest)?,
        4,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn cross_verify_finalize_outgoing_channel_closure() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let dest: Address = [0xef; Address::SIZE].into();

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *B_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *S_ADDRS);

    assert_signed_eq!(
        "finalize_closure",
        b_gen.finalize_outgoing_channel_closure(dest)?,
        s_gen.finalize_outgoing_channel_closure(dest)?,
        4,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn cross_verify_register_safe_by_node() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let safe: Address = [0x55; Address::SIZE].into();

    let b_gen = bindings_based::BasicPayloadGenerator::new((&key).into(), *B_ADDRS);
    let s_gen = static_based::BasicPayloadGenerator::new((&key).into(), *S_ADDRS);

    assert_signed_eq!(
        "register_safe",
        b_gen.register_safe_by_node(safe)?,
        s_gen.register_safe_by_node(safe)?,
        7,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn cross_verify_deregister_node_by_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let module: Address = [1u8; Address::SIZE].into();

    let b_gen = bindings_based::SafePayloadGenerator::new(&key, *B_ADDRS, module);
    let s_gen = static_based::SafePayloadGenerator::new(&key, *S_ADDRS, module);

    assert_signed_eq!(
        "deregister_node",
        b_gen.deregister_node_by_safe()?,
        s_gen.deregister_node_by_safe()?,
        8,
        1,
        &key
    );
    Ok(())
}
