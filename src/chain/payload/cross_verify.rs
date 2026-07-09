//! Cross-verification tests comparing the full signed EIP-1559 bytes produced by the
//! alloy-backed `bindings_based` implementation against the manual `static_based` one.
//!
//! These tests run unconditionally: `hopr-bindings` is a dev-dependency so both
//! implementations are always compiled during `cargo test`, regardless of whether the
//! `use-bindings` production feature is active.

#![cfg(test)]

use multiaddr::Multiaddr;
use std::str::FromStr;

use crate::chain::payload::tests::{
    CONTRACT_ADDRS_JSON, PRIVATE_KEY_1, PRIVATE_KEY_2, REDEEMABLE_TICKET,
};
use crate::chain::payload::{PayloadGenerator, SignableTransaction, bindings_based, static_based};
use crate::crypto::prelude::*;
use crate::internal::prelude::*;
use crate::primitive::prelude::*;

lazy_static::lazy_static! {
    // bindings_based always uses hopr_bindings::ContractAddresses (available as dev-dep).
    static ref B_ADDRS: hopr_bindings::ContractAddresses = serde_json::from_str(CONTRACT_ADDRS_JSON).unwrap();
    // static_based uses crate::chain::ContractAddresses (local struct when not use-bindings).
    static ref S_ADDRS: crate::chain::ContractAddresses = serde_json::from_str(CONTRACT_ADDRS_JSON).unwrap();
    // Shared Safe module address used across all `SafePayloadGenerator` tests below.
    static ref MODULE: Address = [1u8; Address::SIZE].into();
}

fn basic_gens(
    key: &ChainKeypair,
) -> (
    bindings_based::BasicPayloadGenerator,
    static_based::BasicPayloadGenerator,
) {
    (
        bindings_based::BasicPayloadGenerator::new(key.into(), *B_ADDRS),
        static_based::BasicPayloadGenerator::new(key.into(), *S_ADDRS),
    )
}

fn safe_gens(
    key: &ChainKeypair,
) -> (
    bindings_based::SafePayloadGenerator,
    static_based::SafePayloadGenerator,
) {
    (
        bindings_based::SafePayloadGenerator::new(key, *B_ADDRS, *MODULE),
        static_based::SafePayloadGenerator::new(key, *S_ADDRS, *MODULE),
    )
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
            const_hex::encode(&*b),
            const_hex::encode(&*s),
        );
    }};
}

#[tokio::test]
async fn announce_basic() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let kb = KeyBinding::new(
        (&key).into(),
        &OffchainKeypair::from_secret(&PRIVATE_KEY_1)?,
    );
    let ma = Multiaddr::from_str("/ip4/1.2.3.4/tcp/56")?;
    let ad = AnnouncementData::new(kb, Some(ma))?;

    let (b_gen, s_gen) = basic_gens(&key);

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
async fn announce_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let kb = KeyBinding::new(
        (&key).into(),
        &OffchainKeypair::from_secret(&PRIVATE_KEY_1)?,
    );
    let ma = Multiaddr::from_str("/ip4/5.6.7.8/tcp/99")?;
    let ad = AnnouncementData::new(kb, Some(ma))?;

    let (b_gen, s_gen) = safe_gens(&key);

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
async fn redeem_ticket_basic() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;
    let ticket = *REDEEMABLE_TICKET;

    let (b_gen, s_gen) = basic_gens(&key);

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
async fn redeem_ticket_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;
    let ticket = *REDEEMABLE_TICKET;

    let (b_gen, s_gen) = safe_gens(&key);

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
async fn withdraw_basic() -> anyhow::Result<()> {
    let key_alice = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let key_bob = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;

    let (b_gen, s_gen) = basic_gens(&key_alice);

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
async fn withdraw_safe() -> anyhow::Result<()> {
    let key_alice = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let key_bob = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;

    let (b_gen, s_gen) = safe_gens(&key_alice);

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
async fn fund_channel() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let dest: Address = [0xab; Address::SIZE].into();

    let (b_gen, s_gen) = basic_gens(&key);

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
async fn fund_channel_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let dest: Address = [0xab; Address::SIZE].into();

    let (b_gen, s_gen) = safe_gens(&key);

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
async fn close_incoming_channel() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let source: Address = [0xcd; Address::SIZE].into();

    let (b_gen, s_gen) = basic_gens(&key);

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
async fn initiate_outgoing_channel_closure() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let dest: Address = [0xef; Address::SIZE].into();

    let (b_gen, s_gen) = basic_gens(&key);

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

    let (b_gen, s_gen) = basic_gens(&key);

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

    let (b_gen, s_gen) = basic_gens(&key);

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
async fn approve_basic() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let spender: Address = [0x11; Address::SIZE].into();

    let (b_gen, s_gen) = basic_gens(&key);

    assert_signed_eq!(
        "approve_basic",
        b_gen.approve(spender, HoprBalance::from(1000))?,
        s_gen.approve(spender, HoprBalance::from(1000))?,
        9,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn approve_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let spender: Address = [0x11; Address::SIZE].into();

    let (b_gen, s_gen) = safe_gens(&key);

    assert_signed_eq!(
        "approve_safe",
        b_gen.approve(spender, HoprBalance::from(1000))?,
        s_gen.approve(spender, HoprBalance::from(1000))?,
        10,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn withdraw_xdai_basic() -> anyhow::Result<()> {
    let key_alice = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let key_bob = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;

    let (b_gen, s_gen) = basic_gens(&key_alice);

    assert_signed_eq!(
        "withdraw_xdai_basic",
        b_gen.transfer((&key_bob).into(), XDaiBalance::from(100))?,
        s_gen.transfer((&key_bob).into(), XDaiBalance::from(100))?,
        11,
        1,
        &key_bob
    );
    Ok(())
}

#[tokio::test]
async fn withdraw_xdai_safe() -> anyhow::Result<()> {
    let key_alice = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let key_bob = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;

    let (b_gen, s_gen) = safe_gens(&key_alice);

    assert_signed_eq!(
        "withdraw_xdai_safe",
        b_gen.transfer((&key_bob).into(), XDaiBalance::from(100))?,
        s_gen.transfer((&key_bob).into(), XDaiBalance::from(100))?,
        12,
        1,
        &key_bob
    );
    Ok(())
}

#[tokio::test]
async fn close_incoming_channel_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let source: Address = [0xcd; Address::SIZE].into();

    let (b_gen, s_gen) = safe_gens(&key);

    assert_signed_eq!(
        "close_incoming_safe",
        b_gen.close_incoming_channel(source)?,
        s_gen.close_incoming_channel(source)?,
        13,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn initiate_outgoing_channel_closure_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let dest: Address = [0xef; Address::SIZE].into();

    let (b_gen, s_gen) = safe_gens(&key);

    assert_signed_eq!(
        "initiate_closure_safe",
        b_gen.initiate_outgoing_channel_closure(dest)?,
        s_gen.initiate_outgoing_channel_closure(dest)?,
        14,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn finalize_outgoing_channel_closure_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let dest: Address = [0xef; Address::SIZE].into();

    let (b_gen, s_gen) = safe_gens(&key);

    assert_signed_eq!(
        "finalize_closure_safe",
        b_gen.finalize_outgoing_channel_closure(dest)?,
        s_gen.finalize_outgoing_channel_closure(dest)?,
        15,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn register_safe_by_node_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let safe: Address = [0x55; Address::SIZE].into();

    let (b_gen, s_gen) = safe_gens(&key);

    assert_signed_eq!(
        "register_safe_safe",
        b_gen.register_safe_by_node(safe)?,
        s_gen.register_safe_by_node(safe)?,
        16,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn deploy_safe_without_node() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let admins: Vec<Address> = vec![[0x22; Address::SIZE].into(), [0x33; Address::SIZE].into()];
    let nonce = [0x44u8; 32];

    let (b_gen, s_gen) = basic_gens(&key);

    assert_signed_eq!(
        "deploy_safe_without_node",
        b_gen.deploy_safe(HoprBalance::from(1000), &admins, false, nonce)?,
        s_gen.deploy_safe(HoprBalance::from(1000), &admins, false, nonce)?,
        17,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn deploy_safe_with_node() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
    let admins: Vec<Address> = vec![[0x22; Address::SIZE].into(), [0x33; Address::SIZE].into()];
    let nonce = [0x44u8; 32];

    let (b_gen, s_gen) = basic_gens(&key);

    assert_signed_eq!(
        "deploy_safe_with_node",
        b_gen.deploy_safe(HoprBalance::from(1000), &admins, true, nonce)?,
        s_gen.deploy_safe(HoprBalance::from(1000), &admins, true, nonce)?,
        18,
        1,
        &key
    );
    Ok(())
}

#[tokio::test]
async fn deregister_node_by_safe() -> anyhow::Result<()> {
    let key = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;

    let (b_gen, s_gen) = safe_gens(&key);

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
