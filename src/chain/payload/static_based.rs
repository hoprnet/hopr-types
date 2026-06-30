//! Payload generators using manual ABI encoding.
//!
//! Function selectors are computed via `sha3::Keccak256` for EIP-1559 transactions signing.
//! The `bindings_based` module is kept as a test module to verify correctness of every encoded payload.

// When `use-bindings` is active this module's types are not re-exported (bindings-based
// types take precedence in the public API), so dead-code warnings are expected.
#![cfg_attr(feature = "use-bindings", allow(dead_code))]

use hex_literal::hex;
use sha3::{Digest, Keccak256};

use crate::chain::{
    ContractAddresses,
    errors::ChainTypesError::{InvalidArguments, InvalidState, SigningError},
    payload::{self, GasEstimation, PayloadGenerator, SignableTransaction},
};
use crate::crypto::prelude::*;
use crate::internal::prelude::*;
use crate::primitive::prelude::*;

// ─── minimal RLP encoder ───────────────────────────────────────────────────

mod rlp {
    fn encode_length(len: usize, offset: u8) -> Vec<u8> {
        if len < 56 {
            vec![offset + len as u8]
        } else {
            let b = len.to_be_bytes();
            let first = b.iter().position(|&x| x != 0).unwrap_or(7);
            let ll = 8 - first;
            let mut out = vec![offset + 55 + ll as u8];
            out.extend_from_slice(&b[first..]);
            out
        }
    }

    /// RLP-encode a raw byte string.
    pub fn bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            return data.to_vec();
        }
        let mut out = encode_length(data.len(), 0x80);
        out.extend_from_slice(data);
        out
    }

    /// RLP-encode a list of already-encoded items.
    pub fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let content: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
        let mut out = encode_length(content.len(), 0xc0);
        out.extend_from_slice(&content);
        out
    }

    /// RLP-encode a u64 as a minimal big-endian integer.
    pub fn uint64(v: u64) -> Vec<u8> {
        if v == 0 {
            return bytes(&[]);
        }
        let b = v.to_be_bytes();
        let first = b.iter().position(|&x| x != 0).unwrap_or(7);
        bytes(&b[first..])
    }

    /// RLP-encode a u128 as a minimal big-endian integer.
    pub fn uint128(v: u128) -> Vec<u8> {
        if v == 0 {
            return bytes(&[]);
        }
        let b = v.to_be_bytes();
        let first = b.iter().position(|&x| x != 0).unwrap_or(15);
        bytes(&b[first..])
    }

    /// RLP-encode a 32-byte big-endian integer (U256) in minimal form.
    pub fn uint256_bytes(v: &[u8; 32]) -> Vec<u8> {
        let first = v.iter().position(|&x| x != 0).unwrap_or(32);
        if first == 32 {
            return bytes(&[]);
        }
        bytes(&v[first..])
    }
}

// ─── ABI encoding helpers ──────────────────────────────────────────────────

/// Computes the 4-byte ABI function selector from the Solidity function signature.
fn sel(sig: &str) -> [u8; 4] {
    let h = Keccak256::digest(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// ABI-encodes an address as 32 bytes (left-zero-padded).
fn addr32(a: [u8; 20]) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[12..].copy_from_slice(&a);
    b
}

/// Converts a usize to a 32-byte big-endian word (for offsets / lengths).
fn word_usize(v: usize) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&(v as u64).to_be_bytes());
    b
}

/// ABI-encodes a `bytes` dynamic type: length word followed by zero-padded data.
fn abi_dyn_tail(data: &[u8]) -> Vec<u8> {
    let pad = (32 - data.len() % 32) % 32;
    let mut out = Vec::with_capacity(32 + data.len() + pad);
    out.extend_from_slice(&word_usize(data.len()));
    out.extend_from_slice(data);
    out.resize(out.len() + pad, 0);
    out
}

/// Builds the encoding for a static-only call (selector + fixed 32-byte words).
fn static_call(selector: [u8; 4], words: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + words.len() * 32);
    out.extend_from_slice(&selector);
    for w in words {
        out.extend_from_slice(w);
    }
    out
}

/// Builds a call with one dynamic `bytes` parameter appended after `n_static` fixed words.
/// Layout: selector | static_words... | offset_word | dynamic_tail
fn call_with_bytes(selector: [u8; 4], static_words: &[[u8; 32]], data: &[u8]) -> Vec<u8> {
    // offset points past all head slots (static words + 1 offset word itself)
    let offset = (static_words.len() + 1) * 32;
    let tail = abi_dyn_tail(data);
    let mut out = Vec::with_capacity(4 + (static_words.len() + 1) * 32 + tail.len());
    out.extend_from_slice(&selector);
    for w in static_words {
        out.extend_from_slice(w);
    }
    out.extend_from_slice(&word_usize(offset));
    out.extend_from_slice(&tail);
    out
}

// ─── Specific ABI call encoders ───────────────────────────────────────────

fn encode_approve(spender: [u8; 20], amount: &[u8; 32]) -> Vec<u8> {
    static_call(sel("approve(address,uint256)"), &[addr32(spender), *amount])
}

fn encode_transfer(recipient: [u8; 20], amount: &[u8; 32]) -> Vec<u8> {
    static_call(
        sel("transfer(address,uint256)"),
        &[addr32(recipient), *amount],
    )
}

/// ERC-777 `send(address,uint256,bytes)`.
fn encode_send(recipient: [u8; 20], amount: &[u8; 32], data: &[u8]) -> Vec<u8> {
    call_with_bytes(
        sel("send(address,uint256,bytes)"),
        &[addr32(recipient), *amount],
        data,
    )
}

fn encode_register_safe_by_node(safe_addr: [u8; 20]) -> Vec<u8> {
    static_call(sel("registerSafeByNode(address)"), &[addr32(safe_addr)])
}

fn encode_deregister_node_by_safe(node_addr: [u8; 20]) -> Vec<u8> {
    static_call(sel("deregisterNodeBySafe(address)"), &[addr32(node_addr)])
}

/// Gnosis Safe module: `execTransactionFromModule(address,uint256,bytes,uint8)`.
fn encode_exec_from_module(to: [u8; 20], call_data: &[u8]) -> Vec<u8> {
    // Layout: selector | to | value(0) | offset | operation(0) | tail
    let offset = 4usize * 32; // 4 head slots → offset = 128
    let tail = abi_dyn_tail(call_data);
    let mut out = Vec::with_capacity(4 + 4 * 32 + tail.len());
    out.extend_from_slice(&sel(
        "execTransactionFromModule(address,uint256,bytes,uint8)",
    ));
    out.extend_from_slice(&addr32(to));
    out.extend_from_slice(&[0u8; 32]); // value = 0
    out.extend_from_slice(&word_usize(offset));
    out.extend_from_slice(&[0u8; 32]); // operation = 0 (Call)
    out.extend_from_slice(&tail);
    out
}

fn encode_fund_channel(account: [u8; 20], amount_96: &[u8; 12]) -> Vec<u8> {
    let mut amount_word = [0u8; 32];
    amount_word[20..].copy_from_slice(amount_96);
    static_call(
        sel("fundChannel(address,uint96)"),
        &[addr32(account), amount_word],
    )
}

fn encode_fund_channel_safe(
    self_addr: [u8; 20],
    account: [u8; 20],
    amount_96: &[u8; 12],
) -> Vec<u8> {
    let mut amount_word = [0u8; 32];
    amount_word[20..].copy_from_slice(amount_96);
    static_call(
        sel("fundChannelSafe(address,address,uint96)"),
        &[addr32(self_addr), addr32(account), amount_word],
    )
}

fn encode_close_incoming_channel(source: [u8; 20]) -> Vec<u8> {
    static_call(sel("closeIncomingChannel(address)"), &[addr32(source)])
}

fn encode_close_incoming_channel_safe(self_addr: [u8; 20], source: [u8; 20]) -> Vec<u8> {
    static_call(
        sel("closeIncomingChannelSafe(address,address)"),
        &[addr32(self_addr), addr32(source)],
    )
}

fn encode_initiate_outgoing_channel_closure(destination: [u8; 20]) -> Vec<u8> {
    static_call(
        sel("initiateOutgoingChannelClosure(address)"),
        &[addr32(destination)],
    )
}

fn encode_initiate_outgoing_channel_closure_safe(
    self_addr: [u8; 20],
    destination: [u8; 20],
) -> Vec<u8> {
    static_call(
        sel("initiateOutgoingChannelClosureSafe(address,address)"),
        &[addr32(self_addr), addr32(destination)],
    )
}

fn encode_finalize_outgoing_channel_closure(destination: [u8; 20]) -> Vec<u8> {
    static_call(
        sel("finalizeOutgoingChannelClosure(address)"),
        &[addr32(destination)],
    )
}

fn encode_finalize_outgoing_channel_closure_safe(
    self_addr: [u8; 20],
    destination: [u8; 20],
) -> Vec<u8> {
    static_call(
        sel("finalizeOutgoingChannelClosureSafe(address,address)"),
        &[addr32(self_addr), addr32(destination)],
    )
}

/// Packs the 16 × 32-byte words that make up `(RedeemableTicket, VRFParameters)`.
/// All fields are static (no dynamic types inside these structs).
fn redeem_ticket_words(
    acked_ticket: &RedeemableTicket,
    me: &Address,
) -> payload::Result<[[u8; 32]; 16]> {
    let sig = acked_ticket
        .verified_ticket()
        .signature
        .as_ref()
        .ok_or(InvalidArguments("Acknowledged ticket must be signed"))?;
    let serialized_sig: &[u8] = sig.as_ref();

    // TicketData
    let channel_id: [u8; 32] = *<&[u8; 32]>::try_from(acked_ticket.ticket.channel_id().as_ref())
        .map_err(|_| InvalidArguments("channel_id length"))?;
    let amount_src = acked_ticket.verified_ticket().amount.amount().to_be_bytes();
    let mut amount_word = [0u8; 32];
    amount_word[20..].copy_from_slice(&amount_src[32 - 12..]);

    let index_src = acked_ticket.verified_ticket().index.to_be_bytes();
    let mut index_word = [0u8; 32];
    index_word[26..].copy_from_slice(&index_src[8 - 6..]);

    let epoch_src = acked_ticket.verified_ticket().channel_epoch.to_be_bytes();
    let mut epoch_word = [0u8; 32];
    epoch_word[29..].copy_from_slice(&epoch_src[4 - 3..]);

    let mut win_prob_word = [0u8; 32];
    win_prob_word[25..].copy_from_slice(&acked_ticket.verified_ticket().encoded_win_prob);

    // CompactSignature
    let mut r = [0u8; 32];
    let mut vs = [0u8; 32];
    r.copy_from_slice(&serialized_sig[0..32]);
    vs.copy_from_slice(&serialized_sig[32..64]);

    // porSecret
    let mut por_secret = [0u8; 32];
    por_secret.copy_from_slice(acked_ticket.response.as_ref());

    // VRFParameters – all computed by our own crypto (no alloy)
    let vp = &acked_ticket.vrf_params;
    let v_pt = vp.get_v_encoded_point();
    let v_bytes = v_pt.as_bytes();
    let s_b = vp
        .get_s_b_witness(
            me,
            <&[u8; 32]>::try_from(acked_ticket.ticket.verified_hash().as_ref())
                .map_err(|_| InvalidArguments("ticket hash length"))?,
            acked_ticket.channel_dst.as_ref(),
        )
        .map_err(|_| InvalidArguments("VRF s_b witness computation failed"))?;
    let sb_bytes = s_b.as_bytes();
    let hv_pt = vp.get_h_v_witness();
    let hv_bytes = hv_pt.as_bytes();

    let mut vx = [0u8; 32];
    let mut vy = [0u8; 32];
    let mut s_w = [0u8; 32];
    let mut h_w = [0u8; 32];
    let mut sbx = [0u8; 32];
    let mut sby = [0u8; 32];
    let mut hvx = [0u8; 32];
    let mut hvy = [0u8; 32];

    vx.copy_from_slice(&v_bytes[1..33]);
    vy.copy_from_slice(&v_bytes[33..65]);
    s_w.copy_from_slice(vp.s.to_bytes().as_ref());
    h_w.copy_from_slice(vp.h.to_bytes().as_ref());
    sbx.copy_from_slice(&sb_bytes[1..33]);
    sby.copy_from_slice(&sb_bytes[33..65]);
    hvx.copy_from_slice(&hv_bytes[1..33]);
    hvy.copy_from_slice(&hv_bytes[33..65]);

    Ok([
        channel_id,
        amount_word,
        index_word,
        epoch_word,
        win_prob_word,
        r,
        vs,
        por_secret,
        vx,
        vy,
        s_w,
        h_w,
        sbx,
        sby,
        hvx,
        hvy,
    ])
}

fn encode_redeem_ticket(acked_ticket: &RedeemableTicket, me: &Address) -> payload::Result<Vec<u8>> {
    const SIG: &str = "redeemTicket(((bytes32,uint96,uint48,uint24,uint56),(bytes32,bytes32),uint256),(uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256))";
    let words = redeem_ticket_words(acked_ticket, me)?;
    Ok(static_call(sel(SIG), &words))
}

fn encode_redeem_ticket_safe(
    self_addr: [u8; 20],
    acked_ticket: &RedeemableTicket,
    me: &Address,
) -> payload::Result<Vec<u8>> {
    const SIG: &str = "redeemTicketSafe(address,((bytes32,uint96,uint48,uint24,uint56),(bytes32,bytes32),uint256),(uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256))";
    let words = redeem_ticket_words(acked_ticket, me)?;
    let mut all = vec![addr32(self_addr)];
    all.extend_from_slice(&words);
    Ok(static_call(sel(SIG), &all))
}

/// Encodes the `KeyBindAndAnnouncePayload` struct body (without the outer 32-byte offset word
/// that `abi_encode()` on a top-level dynamic struct would prepend in alloy).
fn encode_key_bind_announce_body(
    caller_node: [u8; 20],
    sig0: &[u8; 32],
    sig1: &[u8; 32],
    pub_key: &[u8; 32],
    multiaddress: &str,
) -> Vec<u8> {
    let ma = multiaddress.as_bytes();
    // 5 fields (4 static + 1 dynamic string); offset = 5 × 32 = 160
    let offset = 5 * 32usize;
    let tail = abi_dyn_tail(ma);
    let mut out = Vec::with_capacity(5 * 32 + tail.len());
    out.extend_from_slice(&addr32(caller_node));
    out.extend_from_slice(sig0);
    out.extend_from_slice(sig1);
    out.extend_from_slice(pub_key);
    out.extend_from_slice(&word_usize(offset));
    out.extend_from_slice(&tail);
    out
}

/// Encodes the `UserData` struct body (without the outer 32-byte offset word).
fn encode_user_data_body(
    function_id: &[u8; 32],
    nonce: &[u8; 32],
    default_target: &[u8; 32],
    admins: &[[u8; 20]],
) -> Vec<u8> {
    // 4 fields (3 static + 1 dynamic address[]); offset = 4 × 32 = 128
    let offset = 4 * 32usize;
    let mut out = Vec::with_capacity(4 * 32 + 32 + admins.len() * 32);
    out.extend_from_slice(function_id);
    out.extend_from_slice(nonce);
    out.extend_from_slice(default_target);
    out.extend_from_slice(&word_usize(offset));
    // array tail: length + each address padded to 32 bytes
    out.extend_from_slice(&word_usize(admins.len()));
    for a in admins {
        out.extend_from_slice(&addr32(*a));
    }
    out
}

/// Builds the `defaultTarget` word from the channels address + capability permissions.
fn make_default_target(channels: [u8; 20]) -> [u8; 32] {
    const CAPABILITY_PERMISSIONS: [u8; 12] = hex!("010103030303030303030303");
    let mut buf = [0u8; 32];
    buf[..20].copy_from_slice(&channels);
    buf[20..].copy_from_slice(&CAPABILITY_PERMISSIONS);
    buf
}

// ─── TransactionRequest type ──────────────────────────────────────────────

/// Minimal EIP-1559 transaction request that the static payload generators return.
#[derive(Debug, Default, Clone)]
pub struct TransactionRequest {
    pub to: Option<[u8; 20]>,
    pub input: Vec<u8>,
    /// Big-endian U256 value (ETH/xDAI to send).
    pub value: [u8; 32],
    pub gas_limit: Option<u64>,
}

impl TransactionRequest {
    fn with_to(mut self, to: [u8; 20]) -> Self {
        self.to = Some(to);
        self
    }
    fn with_input(mut self, input: Vec<u8>) -> Self {
        self.input = input;
        self
    }
    fn with_value(mut self, value: [u8; 32]) -> Self {
        self.value = value;
        self
    }
    fn with_gas_limit(mut self, gas: u64) -> Self {
        self.gas_limit = Some(gas);
        self
    }
}

// ─── EIP-1559 signing ─────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SignableTransaction for TransactionRequest {
    async fn sign_and_encode_to_eip2718(
        self,
        nonce: u64,
        chain_id: u64,
        max_gas: Option<GasEstimation>,
        chain_keypair: &ChainKeypair,
    ) -> payload::Result<Box<[u8]>> {
        let max_gas = max_gas.unwrap_or_default();
        // Mirror bindings_based behaviour: max_gas.gas_limit always wins.
        let gas_limit = max_gas.gas_limit;

        let to_bytes: &[u8] = match self.to.as_ref() {
            Some(addr) => addr.as_slice(),
            None => &[],
        };

        let build_fields = |with_sig: bool, y: u64, r: &[u8; 32], s: &[u8; 32]| -> Vec<Vec<u8>> {
            let mut fields = vec![
                rlp::uint64(chain_id),
                rlp::uint64(nonce),
                rlp::uint128(max_gas.max_priority_fee_per_gas),
                rlp::uint128(max_gas.max_fee_per_gas),
                rlp::uint64(gas_limit),
                rlp::bytes(to_bytes),
                rlp::uint256_bytes(&self.value),
                rlp::bytes(&self.input),
                rlp::list(&[]), // access_list = []
            ];
            if with_sig {
                fields.push(rlp::uint64(y));
                fields.push(rlp::bytes(r));
                fields.push(rlp::bytes(s));
            }
            fields
        };

        // Signing payload: 0x02 || RLP([..unsigned fields..])
        let unsigned_fields = build_fields(false, 0, &[0; 32], &[0; 32]);
        let unsigned_rlp = rlp::list(&unsigned_fields);
        let mut to_sign = Vec::with_capacity(1 + unsigned_rlp.len());
        to_sign.push(0x02);
        to_sign.extend_from_slice(&unsigned_rlp);

        let hash: [u8; 32] = Keccak256::digest(&to_sign).into();

        // Sign with k256
        let signing_key =
            k256::ecdsa::SigningKey::from_bytes(chain_keypair.secret().as_ref().into())
                .map_err(|e| SigningError(e.into()))?;
        let (sig, rec_id) = signing_key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| SigningError(e.into()))?;
        let sig_bytes = sig.to_bytes();
        let y_parity = rec_id.to_byte() as u64;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[..32]);
        s.copy_from_slice(&sig_bytes[32..]);

        // Final signed transaction
        let signed_fields = build_fields(true, y_parity, &r, &s);
        let signed_rlp = rlp::list(&signed_fields);
        let mut encoded = Vec::with_capacity(1 + signed_rlp.len());
        encoded.push(0x02);
        encoded.extend_from_slice(&signed_rlp);

        Ok(encoded.into_boxed_slice())
    }
}

// ─── BasicPayloadGenerator ────────────────────────────────────────────────

const DEFAULT_TX_GAS: u64 = 400_000;

/// Generates transaction payloads that do not use Safe-compliant ABI.
#[derive(Debug, Clone, Copy)]
pub struct BasicPayloadGenerator {
    me: Address,
    contract_addrs: ContractAddresses,
}

impl BasicPayloadGenerator {
    pub fn new(me: Address, contract_addrs: ContractAddresses) -> Self {
        Self { me, contract_addrs }
    }
}

impl PayloadGenerator for BasicPayloadGenerator {
    type TxRequest = TransactionRequest;

    fn approve(&self, spender: Address, amount: HoprBalance) -> payload::Result<Self::TxRequest> {
        let amount_word = u256_from_balance(&amount);
        Ok(TransactionRequest::default()
            .with_input(encode_approve(spender.into(), &amount_word))
            .with_to(self.contract_addrs.token.into()))
    }

    fn transfer<C: Currency>(
        &self,
        destination: Address,
        amount: Balance<C>,
    ) -> payload::Result<Self::TxRequest> {
        if XDai::is::<C>() {
            let amount_word = u256_from_amount(&amount.amount().to_be_bytes());
            Ok(TransactionRequest::default()
                .with_to(destination.into())
                .with_value(amount_word))
        } else if WxHOPR::is::<C>() {
            let amount_word = u256_from_amount(&amount.amount().to_be_bytes());
            Ok(TransactionRequest::default()
                .with_input(encode_transfer(destination.into(), &amount_word))
                .with_to(self.contract_addrs.token.into()))
        } else {
            Err(InvalidArguments("invalid currency"))
        }
    }

    fn announce(
        &self,
        announcement: AnnouncementData,
        key_binding_fee: HoprBalance,
    ) -> payload::Result<Self::TxRequest> {
        let sig = announcement.key_binding().signature.as_ref();
        let mut sig0 = [0u8; 32];
        let mut sig1 = [0u8; 32];
        sig0.copy_from_slice(&sig[0..32]);
        sig1.copy_from_slice(&sig[32..64]);

        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(announcement.key_binding().packet_key.as_ref());

        let multiaddr_str = announcement
            .multiaddress()
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();

        let inner =
            encode_key_bind_announce_body(self.me.into(), &sig0, &sig1, &pub_key, &multiaddr_str);

        let fee_word = u256_from_balance(&key_binding_fee);
        let call_data = encode_send(self.contract_addrs.announcements.into(), &fee_word, &inner);

        Ok(TransactionRequest::default()
            .with_input(call_data)
            .with_to(self.contract_addrs.token.into()))
    }

    fn fund_channel(&self, dest: Address, amount: HoprBalance) -> payload::Result<Self::TxRequest> {
        if dest.eq(&self.me) {
            return Err(InvalidArguments("Cannot fund channel to self"));
        }
        let src = amount.amount().to_be_bytes();
        let amount_96: &[u8; 12] = <&[u8; 12]>::try_from(&src[32 - 12..])
            .map_err(|_| InvalidArguments("amount conversion"))?;
        Ok(TransactionRequest::default()
            .with_input(encode_fund_channel(dest.into(), amount_96))
            .with_to(self.contract_addrs.channels.into()))
    }

    fn close_incoming_channel(&self, source: Address) -> payload::Result<Self::TxRequest> {
        if source.eq(&self.me) {
            return Err(InvalidArguments("Cannot close incoming channel from self"));
        }
        Ok(TransactionRequest::default()
            .with_input(encode_close_incoming_channel(source.into()))
            .with_to(self.contract_addrs.channels.into()))
    }

    fn initiate_outgoing_channel_closure(
        &self,
        destination: Address,
    ) -> payload::Result<Self::TxRequest> {
        if destination.eq(&self.me) {
            return Err(InvalidArguments(
                "Cannot initiate closure of incoming channel to self",
            ));
        }
        Ok(TransactionRequest::default()
            .with_input(encode_initiate_outgoing_channel_closure(destination.into()))
            .with_to(self.contract_addrs.channels.into()))
    }

    fn finalize_outgoing_channel_closure(
        &self,
        destination: Address,
    ) -> payload::Result<Self::TxRequest> {
        if destination.eq(&self.me) {
            return Err(InvalidArguments(
                "Cannot initiate closure of incoming channel to self",
            ));
        }
        Ok(TransactionRequest::default()
            .with_input(encode_finalize_outgoing_channel_closure(destination.into()))
            .with_to(self.contract_addrs.channels.into()))
    }

    fn redeem_ticket(&self, acked_ticket: RedeemableTicket) -> payload::Result<Self::TxRequest> {
        Ok(TransactionRequest::default()
            .with_input(encode_redeem_ticket(&acked_ticket, &self.me)?)
            .with_to(self.contract_addrs.channels.into()))
    }

    fn register_safe_by_node(&self, safe_addr: Address) -> payload::Result<Self::TxRequest> {
        Ok(TransactionRequest::default()
            .with_input(encode_register_safe_by_node(safe_addr.into()))
            .with_to(self.contract_addrs.node_safe_registry.into()))
    }

    fn deregister_node_by_safe(&self) -> payload::Result<Self::TxRequest> {
        Err(InvalidState(
            "Can only deregister an address if Safe is activated",
        ))
    }

    fn deploy_safe(
        &self,
        balance: HoprBalance,
        admins: &[Address],
        include_node: bool,
        nonce: [u8; 32],
    ) -> payload::Result<Self::TxRequest> {
        let function_id: [u8; 32] = if include_node {
            hex!("0105b97dcdf19d454ebe36f91ed516c2b90ee79f4a46af96a0138c1f5403c1cc")
        } else {
            hex!("dd24c144db91d1bc600aac99393baf8f8c664ba461188f057e37f2c37b962b45")
        };
        let default_target = make_default_target(self.contract_addrs.channels.into());
        let admins_raw: Vec<[u8; 20]> = admins.iter().map(|a| (*a).into()).collect();
        let user_data = encode_user_data_body(&function_id, &nonce, &default_target, &admins_raw);
        let balance_word = u256_from_balance(&balance);
        let tx_payload = encode_send(
            self.contract_addrs.node_stake_factory.into(),
            &balance_word,
            &user_data,
        );
        Ok(TransactionRequest::default()
            .with_to(self.contract_addrs.token.into())
            .with_input(tx_payload))
    }
}

// ─── SafePayloadGenerator ─────────────────────────────────────────────────

/// Payload generator that wraps all channel calls through the Safe module.
#[derive(Debug, Clone, Copy)]
pub struct SafePayloadGenerator {
    me: Address,
    contract_addrs: ContractAddresses,
    module: Address,
}

impl SafePayloadGenerator {
    pub fn new(
        chain_keypair: &ChainKeypair,
        contract_addrs: ContractAddresses,
        module: Address,
    ) -> Self {
        Self {
            me: chain_keypair.into(),
            contract_addrs,
            module,
        }
    }
}

impl PayloadGenerator for SafePayloadGenerator {
    type TxRequest = TransactionRequest;

    fn approve(&self, spender: Address, amount: HoprBalance) -> payload::Result<Self::TxRequest> {
        let amount_word = u256_from_balance(&amount);
        Ok(TransactionRequest::default()
            .with_input(encode_approve(spender.into(), &amount_word))
            .with_to(self.contract_addrs.token.into())
            .with_gas_limit(DEFAULT_TX_GAS))
    }

    fn transfer<C: Currency>(
        &self,
        destination: Address,
        amount: Balance<C>,
    ) -> payload::Result<Self::TxRequest> {
        if XDai::is::<C>() {
            let amount_word = u256_from_amount(&amount.amount().to_be_bytes());
            Ok(TransactionRequest::default()
                .with_to(destination.into())
                .with_value(amount_word)
                .with_gas_limit(DEFAULT_TX_GAS))
        } else if WxHOPR::is::<C>() {
            let amount_word = u256_from_amount(&amount.amount().to_be_bytes());
            Ok(TransactionRequest::default()
                .with_input(encode_transfer(destination.into(), &amount_word))
                .with_to(self.contract_addrs.token.into())
                .with_gas_limit(DEFAULT_TX_GAS))
        } else {
            Err(InvalidArguments("invalid currency"))
        }
    }

    fn announce(
        &self,
        announcement: AnnouncementData,
        key_binding_fee: HoprBalance,
    ) -> payload::Result<Self::TxRequest> {
        let sig = announcement.key_binding().signature.as_ref();
        let mut sig0 = [0u8; 32];
        let mut sig1 = [0u8; 32];
        sig0.copy_from_slice(&sig[0..32]);
        sig1.copy_from_slice(&sig[32..64]);

        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(announcement.key_binding().packet_key.as_ref());

        let multiaddr_str = announcement
            .multiaddress()
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();

        let inner =
            encode_key_bind_announce_body(self.me.into(), &sig0, &sig1, &pub_key, &multiaddr_str);

        let fee_word = u256_from_balance(&key_binding_fee);
        let send_call = encode_send(self.contract_addrs.announcements.into(), &fee_word, &inner);

        let module_call = encode_exec_from_module(self.contract_addrs.token.into(), &send_call);

        Ok(TransactionRequest::default()
            .with_input(module_call)
            .with_to(self.module.into())
            .with_gas_limit(DEFAULT_TX_GAS))
    }

    fn fund_channel(&self, dest: Address, amount: HoprBalance) -> payload::Result<Self::TxRequest> {
        if dest.eq(&self.me) {
            return Err(InvalidArguments("cannot fund channel to self"));
        }
        if amount.amount()
            > crate::primitive::prelude::U256::from(ChannelBuilder::MAX_FUNDING_AMOUNT)
        {
            return Err(InvalidArguments(
                "cannot fund channel with amount larger than MAX_FUNDING_AMOUNT",
            ));
        }
        let src = amount.amount().to_be_bytes();
        let amount_96: &[u8; 12] = <&[u8; 12]>::try_from(&src[32 - 12..])
            .map_err(|_| InvalidArguments("amount conversion"))?;
        let call_data = encode_fund_channel_safe(self.me.into(), dest.into(), amount_96);
        Ok(TransactionRequest::default()
            .with_input(encode_exec_from_module(
                self.contract_addrs.channels.into(),
                &call_data,
            ))
            .with_to(self.module.into())
            .with_gas_limit(DEFAULT_TX_GAS))
    }

    fn close_incoming_channel(&self, source: Address) -> payload::Result<Self::TxRequest> {
        if source.eq(&self.me) {
            return Err(InvalidArguments("Cannot close incoming channel from self"));
        }
        let call_data = encode_close_incoming_channel_safe(self.me.into(), source.into());
        Ok(TransactionRequest::default()
            .with_input(encode_exec_from_module(
                self.contract_addrs.channels.into(),
                &call_data,
            ))
            .with_to(self.module.into())
            .with_gas_limit(DEFAULT_TX_GAS))
    }

    fn initiate_outgoing_channel_closure(
        &self,
        destination: Address,
    ) -> payload::Result<Self::TxRequest> {
        if destination.eq(&self.me) {
            return Err(InvalidArguments(
                "Cannot initiate closure of incoming channel to self",
            ));
        }
        let call_data =
            encode_initiate_outgoing_channel_closure_safe(self.me.into(), destination.into());
        Ok(TransactionRequest::default()
            .with_input(encode_exec_from_module(
                self.contract_addrs.channels.into(),
                &call_data,
            ))
            .with_to(self.module.into())
            .with_gas_limit(DEFAULT_TX_GAS))
    }

    fn finalize_outgoing_channel_closure(
        &self,
        destination: Address,
    ) -> payload::Result<Self::TxRequest> {
        if destination.eq(&self.me) {
            return Err(InvalidArguments(
                "Cannot initiate closure of incoming channel to self",
            ));
        }
        let call_data =
            encode_finalize_outgoing_channel_closure_safe(self.me.into(), destination.into());
        Ok(TransactionRequest::default()
            .with_input(encode_exec_from_module(
                self.contract_addrs.channels.into(),
                &call_data,
            ))
            .with_to(self.module.into())
            .with_gas_limit(DEFAULT_TX_GAS))
    }

    fn redeem_ticket(&self, acked_ticket: RedeemableTicket) -> payload::Result<Self::TxRequest> {
        let call_data = encode_redeem_ticket_safe(self.me.into(), &acked_ticket, &self.me)?;
        Ok(TransactionRequest::default()
            .with_input(encode_exec_from_module(
                self.contract_addrs.channels.into(),
                &call_data,
            ))
            .with_to(self.module.into())
            .with_gas_limit(DEFAULT_TX_GAS))
    }

    fn register_safe_by_node(&self, safe_addr: Address) -> payload::Result<Self::TxRequest> {
        Ok(TransactionRequest::default()
            .with_input(encode_register_safe_by_node(safe_addr.into()))
            .with_to(self.contract_addrs.node_safe_registry.into())
            .with_gas_limit(DEFAULT_TX_GAS))
    }

    fn deregister_node_by_safe(&self) -> payload::Result<Self::TxRequest> {
        Ok(TransactionRequest::default()
            .with_input(encode_deregister_node_by_safe(self.me.into()))
            .with_to(self.module.into())
            .with_gas_limit(DEFAULT_TX_GAS))
    }

    fn deploy_safe(
        &self,
        _: HoprBalance,
        _: &[Address],
        _: bool,
        _: [u8; 32],
    ) -> payload::Result<Self::TxRequest> {
        Err(InvalidState("cannot deploy Safe from SafePayloadGenerator"))
    }
}

// ─── Conversion helpers ───────────────────────────────────────────────────

/// Converts a 32-byte primitive U256 big-endian representation to a 32-byte word.
fn u256_from_amount(src: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    let n = src.len().min(32);
    w[32 - n..].copy_from_slice(&src[src.len() - n..]);
    w
}

fn u256_from_balance(balance: &HoprBalance) -> [u8; 32] {
    u256_from_amount(&balance.amount().to_be_bytes())
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use multiaddr::Multiaddr;

    use super::{BasicPayloadGenerator, SafePayloadGenerator};
    use crate::chain::payload::tests::{CONTRACT_ADDRS_JSON, PRIVATE_KEY_1, PRIVATE_KEY_2, REDEEMABLE_TICKET};
    use crate::chain::payload::{PayloadGenerator, SignableTransaction};
    use crate::crypto::prelude::*;
    use crate::internal::prelude::*;
    use crate::primitive::prelude::*;

    lazy_static::lazy_static! {
        static ref CONTRACT_ADDRS: crate::chain::ContractAddresses = serde_json::from_str(CONTRACT_ADDRS_JSON).unwrap();
    }
    #[tokio::test]
    async fn test_announce() -> anyhow::Result<()> {
        let test_multiaddr = Multiaddr::from_str("/ip4/1.2.3.4/tcp/56")?;
        let chain_key_0 = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
        let generator = BasicPayloadGenerator::new((&chain_key_0).into(), *CONTRACT_ADDRS);
        let kb = KeyBinding::new(
            (&chain_key_0).into(),
            &OffchainKeypair::from_secret(&PRIVATE_KEY_1)?,
        );
        let ad = AnnouncementData::new(kb, Some(test_multiaddr))?;
        let signed_tx = generator
            .announce(ad, 100_u32.into())?
            .sign_and_encode_to_eip2718(2, 1, None, &chain_key_0)
            .await?;
        insta::assert_snapshot!("announce_basic", hex::encode(signed_tx));

        let test_multiaddr_reannounce = Multiaddr::from_str("/ip4/5.6.7.8/tcp/99")?;
        let ad_reannounce = AnnouncementData::new(kb, Some(test_multiaddr_reannounce))?;
        let signed_tx = generator
            .announce(ad_reannounce, 0_u32.into())?
            .sign_and_encode_to_eip2718(1, 1, None, &chain_key_0)
            .await?;
        insta::assert_snapshot!("announce_safe", hex::encode(signed_tx.clone()));

        Ok(())
    }

    #[tokio::test]
    async fn redeem_ticket_basic() -> anyhow::Result<()> {
        let chain_key_bob = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;
        let acked_ticket = *REDEEMABLE_TICKET;
        let generator = BasicPayloadGenerator::new((&chain_key_bob).into(), *CONTRACT_ADDRS);
        let signed_tx = generator
            .redeem_ticket(acked_ticket)?
            .sign_and_encode_to_eip2718(1, 1, None, &chain_key_bob)
            .await?;
        insta::assert_snapshot!("redeem_ticket_basic", hex::encode(signed_tx));
        Ok(())
    }

    #[tokio::test]
    async fn redeem_ticket_safe() -> anyhow::Result<()> {
        let chain_key_bob = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;
        let acked_ticket = *REDEEMABLE_TICKET;
        let generator =
            SafePayloadGenerator::new(&chain_key_bob, *CONTRACT_ADDRS, [1u8; Address::SIZE].into());
        let signed_tx = generator
            .redeem_ticket(acked_ticket)?
            .sign_and_encode_to_eip2718(2, 1, None, &chain_key_bob)
            .await?;
        insta::assert_snapshot!("redeem_ticket_safe", hex::encode(signed_tx));
        Ok(())
    }

    #[tokio::test]
    async fn withdraw_token() -> anyhow::Result<()> {
        let chain_key_alice = ChainKeypair::from_secret(&PRIVATE_KEY_1)?;
        let chain_key_bob = ChainKeypair::from_secret(&PRIVATE_KEY_2)?;

        let generator = BasicPayloadGenerator::new((&chain_key_alice).into(), *CONTRACT_ADDRS);
        let tx = generator.transfer((&chain_key_bob).into(), HoprBalance::from(100))?;
        let signed_tx = tx
            .sign_and_encode_to_eip2718(1, 1, None, &chain_key_bob)
            .await?;
        insta::assert_snapshot!("withdraw_basic", hex::encode(signed_tx));

        let generator = SafePayloadGenerator::new(
            &chain_key_alice,
            *CONTRACT_ADDRS,
            [1u8; Address::SIZE].into(),
        );
        let tx = generator.transfer((&chain_key_bob).into(), HoprBalance::from(100))?;
        let signed_tx = tx
            .sign_and_encode_to_eip2718(2, 1, None, &chain_key_bob)
            .await?;
        insta::assert_snapshot!("withdraw_safe", hex::encode(signed_tx));

        Ok(())
    }
}
