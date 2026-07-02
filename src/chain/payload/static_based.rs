//! Payload generators using manual ABI encoding.
//!
//! Function selectors (see the `selectors` module) are hardcoded `keccak256(signature)[..4]`
//! constants; `sha3::Keccak256` itself is only used at runtime to hash the transaction payload
//! for EIP-1559 signing.
//! The `bindings_based` module is kept as a test module to verify correctness of every encoded payload.

// When `use-bindings` is active this module's types are not re-exported (bindings-based
// types take precedence in the public API), so dead-code warnings are expected.
#![cfg_attr(feature = "use-bindings", allow(dead_code))]

use hex_literal::hex;
use rlp::RlpStream;
use sha3::{Digest, Keccak256};

use crate::chain::{
    ContractAddresses,
    errors::ChainTypesError::{InvalidArguments, InvalidState, SigningError},
    payload::{self, GasEstimation, PayloadGenerator, SignableTransaction},
};
use crate::crypto::prelude::*;
use crate::internal::prelude::*;
use crate::primitive::prelude::*;

/// Strips leading zero bytes from a big-endian integer, as required for canonical RLP integer
/// encoding of values wider than the `rlp` crate's built-in integer impls (up to `u128`).
fn trim_be(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

// ─── ABI function selectors ────────────────────────────────────────────────

/// Precomputed 4-byte ABI selectors (the first 4 bytes of `keccak256(signature)`) for every
/// contract function called from this module. Each is checked against the signature in its doc
/// comment by the `cross_verify` tests (which compare against the `alloy`-bindings encoding).
mod selectors {
    use hex_literal::hex;

    /// `approve(address,uint256)`
    pub const APPROVE: [u8; 4] = hex!("095ea7b3");
    /// `transfer(address,uint256)`
    pub const TRANSFER: [u8; 4] = hex!("a9059cbb");
    /// ERC-777 `send(address,uint256,bytes)`
    pub const SEND: [u8; 4] = hex!("9bd9bbc6");
    /// `registerSafeByNode(address)`
    pub const REGISTER_SAFE_BY_NODE: [u8; 4] = hex!("7f935931");
    /// `deregisterNodeBySafe(address)`
    pub const DEREGISTER_NODE_BY_SAFE: [u8; 4] = hex!("91607c4c");
    /// Gnosis Safe `execTransactionFromModule(address,uint256,bytes,uint8)`
    pub const EXEC_TRANSACTION_FROM_MODULE: [u8; 4] = hex!("468721a7");
    /// `fundChannel(address,uint96)`
    pub const FUND_CHANNEL: [u8; 4] = hex!("fc55309a");
    /// `fundChannelSafe(address,address,uint96)`
    pub const FUND_CHANNEL_SAFE: [u8; 4] = hex!("0abec58f");
    /// `closeIncomingChannel(address)`
    pub const CLOSE_INCOMING_CHANNEL: [u8; 4] = hex!("1a7ffe7a");
    /// `closeIncomingChannelSafe(address,address)`
    pub const CLOSE_INCOMING_CHANNEL_SAFE: [u8; 4] = hex!("54a2edf5");
    /// `initiateOutgoingChannelClosure(address)`
    pub const INITIATE_OUTGOING_CHANNEL_CLOSURE: [u8; 4] = hex!("7c8e28da");
    /// `initiateOutgoingChannelClosureSafe(address,address)`
    pub const INITIATE_OUTGOING_CHANNEL_CLOSURE_SAFE: [u8; 4] = hex!("bda65f45");
    /// `finalizeOutgoingChannelClosure(address)`
    pub const FINALIZE_OUTGOING_CHANNEL_CLOSURE: [u8; 4] = hex!("23cb3ac0");
    /// `finalizeOutgoingChannelClosureSafe(address,address)`
    pub const FINALIZE_OUTGOING_CHANNEL_CLOSURE_SAFE: [u8; 4] = hex!("651514bf");
    /// `redeemTicket(((bytes32,uint96,uint48,uint24,uint56),(bytes32,bytes32),uint256),(uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256))`
    pub const REDEEM_TICKET: [u8; 4] = hex!("65e3fa72");
    /// `redeemTicketSafe(address,((bytes32,uint96,uint48,uint24,uint56),(bytes32,bytes32),uint256),(uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256))`
    pub const REDEEM_TICKET_SAFE: [u8; 4] = hex!("2d50b18b");
}

// ─── ABI encoding helpers ──────────────────────────────────────────────────

/// Right-aligns a big-endian byte slice (at most 32 bytes) into a zero-padded 32-byte word.
fn right_align32(data: &[u8]) -> [u8; 32] {
    U256::from_big_endian(data).to_big_endian()
}

/// ABI-encodes an address as 32 bytes (left-zero-padded).
fn addr32(a: [u8; 20]) -> [u8; 32] {
    right_align32(&a)
}

/// Truncates a big-endian integer to its low `keep` bytes, then right-aligns those into a
/// zero-padded 32-byte ABI word. Used for values ABI-typed narrower than 256 bits (e.g.
/// `uint96`, `uint48`, `uint24`) that are still held as a wider Rust integer.
fn truncated_word(full: &[u8], keep: usize) -> [u8; 32] {
    right_align32(&full[full.len() - keep..])
}

/// Converts a usize to a 32-byte big-endian word (for offsets / lengths).
fn word_usize(v: usize) -> [u8; 32] {
    right_align32(&(v as u64).to_be_bytes())
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
    static_call(selectors::APPROVE, &[addr32(spender), *amount])
}

fn encode_transfer(recipient: [u8; 20], amount: &[u8; 32]) -> Vec<u8> {
    static_call(selectors::TRANSFER, &[addr32(recipient), *amount])
}

fn encode_send(recipient: [u8; 20], amount: &[u8; 32], data: &[u8]) -> Vec<u8> {
    call_with_bytes(selectors::SEND, &[addr32(recipient), *amount], data)
}

fn encode_register_safe_by_node(safe_addr: [u8; 20]) -> Vec<u8> {
    static_call(selectors::REGISTER_SAFE_BY_NODE, &[addr32(safe_addr)])
}

fn encode_deregister_node_by_safe(node_addr: [u8; 20]) -> Vec<u8> {
    static_call(selectors::DEREGISTER_NODE_BY_SAFE, &[addr32(node_addr)])
}

/// Gnosis Safe module: `execTransactionFromModule(address,uint256,bytes,uint8)`.
fn encode_exec_from_module(to: [u8; 20], call_data: &[u8]) -> Vec<u8> {
    // Layout: selector | to | value(0) | offset | operation(0) | tail
    let offset = 4usize * 32; // 4 head slots → offset = 128
    let tail = abi_dyn_tail(call_data);
    let mut out = Vec::with_capacity(4 + 4 * 32 + tail.len());
    out.extend_from_slice(&selectors::EXEC_TRANSACTION_FROM_MODULE);
    out.extend_from_slice(&addr32(to));
    out.extend_from_slice(&[0u8; 32]); // value = 0
    out.extend_from_slice(&word_usize(offset));
    out.extend_from_slice(&[0u8; 32]); // operation = 0 (Call)
    out.extend_from_slice(&tail);
    out
}

fn encode_fund_channel(account: [u8; 20], amount_word: [u8; 32]) -> Vec<u8> {
    static_call(selectors::FUND_CHANNEL, &[addr32(account), amount_word])
}

fn encode_fund_channel_safe(
    self_addr: [u8; 20],
    account: [u8; 20],
    amount_word: [u8; 32],
) -> Vec<u8> {
    static_call(
        selectors::FUND_CHANNEL_SAFE,
        &[addr32(self_addr), addr32(account), amount_word],
    )
}

fn encode_close_incoming_channel(source: [u8; 20]) -> Vec<u8> {
    static_call(selectors::CLOSE_INCOMING_CHANNEL, &[addr32(source)])
}

fn encode_close_incoming_channel_safe(self_addr: [u8; 20], source: [u8; 20]) -> Vec<u8> {
    static_call(
        selectors::CLOSE_INCOMING_CHANNEL_SAFE,
        &[addr32(self_addr), addr32(source)],
    )
}

fn encode_initiate_outgoing_channel_closure(destination: [u8; 20]) -> Vec<u8> {
    static_call(
        selectors::INITIATE_OUTGOING_CHANNEL_CLOSURE,
        &[addr32(destination)],
    )
}

fn encode_initiate_outgoing_channel_closure_safe(
    self_addr: [u8; 20],
    destination: [u8; 20],
) -> Vec<u8> {
    static_call(
        selectors::INITIATE_OUTGOING_CHANNEL_CLOSURE_SAFE,
        &[addr32(self_addr), addr32(destination)],
    )
}

fn encode_finalize_outgoing_channel_closure(destination: [u8; 20]) -> Vec<u8> {
    static_call(
        selectors::FINALIZE_OUTGOING_CHANNEL_CLOSURE,
        &[addr32(destination)],
    )
}

fn encode_finalize_outgoing_channel_closure_safe(
    self_addr: [u8; 20],
    destination: [u8; 20],
) -> Vec<u8> {
    static_call(
        selectors::FINALIZE_OUTGOING_CHANNEL_CLOSURE_SAFE,
        &[addr32(self_addr), addr32(destination)],
    )
}

/// Splits a 65-byte uncompressed SEC1 elliptic-curve point (`0x04 || X || Y`) into its X and Y
/// coordinates, each right-aligned into a 32-byte ABI word.
fn point_xy_words(uncompressed_point: &[u8]) -> ([u8; 32], [u8; 32]) {
    (
        right_align32(&uncompressed_point[1..33]),
        right_align32(&uncompressed_point[33..65]),
    )
}

/// Splits a 64-byte compact signature (`r || s`) into its two 32-byte halves.
fn split64(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    (right_align32(&bytes[0..32]), right_align32(&bytes[32..64]))
}

/// Packs the 8 × 32-byte words of the Solidity `RedeemableTicket` struct: `TicketData` (5
/// words), `CompactSignature` (2 words), and `porSecret` (1 word).
fn redeemable_ticket_words(acked_ticket: &RedeemableTicket) -> payload::Result<[[u8; 32]; 8]> {
    let sig = acked_ticket
        .verified_ticket()
        .signature
        .as_ref()
        .ok_or(InvalidArguments("Acknowledged ticket must be signed"))?;
    let serialized_sig: &[u8] = sig.as_ref();

    // TicketData
    let channel_id: [u8; 32] = *<&[u8; 32]>::try_from(acked_ticket.ticket.channel_id().as_ref())
        .map_err(|_| InvalidArguments("channel_id length"))?;
    let amount_word = truncated_word(
        &acked_ticket.verified_ticket().amount.amount().to_be_bytes(),
        12,
    );
    let index_word = truncated_word(&acked_ticket.verified_ticket().index.to_be_bytes(), 6);
    let epoch_word = truncated_word(
        &acked_ticket.verified_ticket().channel_epoch.to_be_bytes(),
        3,
    );
    let win_prob_word = right_align32(&acked_ticket.verified_ticket().encoded_win_prob);

    // CompactSignature
    let (r, vs) = split64(serialized_sig);

    // porSecret
    let por_secret = right_align32(acked_ticket.response.as_ref());

    Ok([
        channel_id,
        amount_word,
        index_word,
        epoch_word,
        win_prob_word,
        r,
        vs,
        por_secret,
    ])
}

/// Packs the 8 × 32-byte words of the Solidity `VRFParameters` struct: the `V`, `s*B`, and
/// `h*V` curve points (2 words each, X then Y) plus the `s` and `h` scalars.
fn vrf_parameters_words(
    acked_ticket: &RedeemableTicket,
    me: &Address,
) -> payload::Result<[[u8; 32]; 8]> {
    let vp = &acked_ticket.vrf_params;

    let (vx, vy) = point_xy_words(vp.get_v_encoded_point().as_bytes());

    let s_b = vp
        .get_s_b_witness(
            me,
            <&[u8; 32]>::try_from(acked_ticket.ticket.verified_hash().as_ref())
                .map_err(|_| InvalidArguments("ticket hash length"))?,
            acked_ticket.channel_dst.as_ref(),
        )
        .map_err(|_| InvalidArguments("VRF s_b witness computation failed"))?;
    let (sbx, sby) = point_xy_words(s_b.as_bytes());

    let (hvx, hvy) = point_xy_words(vp.get_h_v_witness().as_bytes());

    let s_w = right_align32(vp.s.to_bytes().as_ref());
    let h_w = right_align32(vp.h.to_bytes().as_ref());

    Ok([vx, vy, s_w, h_w, sbx, sby, hvx, hvy])
}

/// Packs the 16 × 32-byte words that make up `(RedeemableTicket, VRFParameters)`.
/// All fields are static (no dynamic types inside these structs).
fn redeem_ticket_words(
    acked_ticket: &RedeemableTicket,
    me: &Address,
) -> payload::Result<[[u8; 32]; 16]> {
    let mut words = [[0u8; 32]; 16];
    words[..8].copy_from_slice(&redeemable_ticket_words(acked_ticket)?);
    words[8..].copy_from_slice(&vrf_parameters_words(acked_ticket, me)?);
    Ok(words)
}

fn encode_redeem_ticket(acked_ticket: &RedeemableTicket, me: &Address) -> payload::Result<Vec<u8>> {
    let words = redeem_ticket_words(acked_ticket, me)?;
    Ok(static_call(selectors::REDEEM_TICKET, &words))
}

fn encode_redeem_ticket_safe(
    self_addr: [u8; 20],
    acked_ticket: &RedeemableTicket,
    me: &Address,
) -> payload::Result<Vec<u8>> {
    let words = redeem_ticket_words(acked_ticket, me)?;
    let mut all = vec![addr32(self_addr)];
    all.extend_from_slice(&words);
    Ok(static_call(selectors::REDEEM_TICKET_SAFE, &all))
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

// ─── Shared per-call TransactionRequest builders ──────────────────────────

fn approve_tx(spender: [u8; 20], amount: &[u8; 32]) -> TransactionRequest {
    TransactionRequest::default().with_input(encode_approve(spender, amount))
}

fn transfer_tx<C: Currency>(
    destination: Address,
    amount: Balance<C>,
) -> payload::Result<TransactionRequest> {
    let amount_word = amount.amount().to_be_bytes();
    if XDai::is::<C>() {
        Ok(TransactionRequest::default().with_value(amount_word))
    } else if WxHOPR::is::<C>() {
        Ok(TransactionRequest::default()
            .with_input(encode_transfer(destination.into(), &amount_word)))
    } else {
        Err(InvalidArguments("invalid currency"))
    }
}

fn register_safe_tx(safe_addr: [u8; 20]) -> TransactionRequest {
    TransactionRequest::default().with_input(encode_register_safe_by_node(safe_addr))
}

/// Builds the `send(announcements, fee, KeyBindAndAnnouncePayload)` call data shared by both generators.
fn announce_call_data(
    me: [u8; 20],
    announcements: [u8; 20],
    announcement: &AnnouncementData,
    key_binding_fee: &HoprBalance,
) -> Vec<u8> {
    let (sig0, sig1) = split64(announcement.key_binding().signature.as_ref());
    let pub_key = right_align32(announcement.key_binding().packet_key.as_ref());

    let multiaddr_str = announcement
        .multiaddress()
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();

    let inner = encode_key_bind_announce_body(me, &sig0, &sig1, &pub_key, &multiaddr_str);
    let fee_word = key_binding_fee.amount().to_be_bytes();
    encode_send(announcements, &fee_word, &inner)
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

        let build_stream = |with_sig: bool, y: u64, r: &[u8; 32], s: &[u8; 32]| -> RlpStream {
            let mut stream = RlpStream::new_list(if with_sig { 12 } else { 9 });
            stream.append(&chain_id);
            stream.append(&nonce);
            stream.append(&max_gas.max_priority_fee_per_gas);
            stream.append(&max_gas.max_fee_per_gas);
            stream.append(&gas_limit);
            stream.append(&to_bytes);
            stream.append(&trim_be(&self.value));
            stream.append(&self.input.as_slice());
            stream.begin_list(0); // access_list = []
            if with_sig {
                stream.append(&y);
                stream.append(&r.as_slice());
                stream.append(&s.as_slice());
            }
            stream
        };

        // Signing payload: 0x02 || RLP([..unsigned fields..])
        let unsigned_rlp = build_stream(false, 0, &[0; 32], &[0; 32]).out();
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
        let signed_rlp = build_stream(true, y_parity, &r, &s).out();
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
        let amount_word = amount.amount().to_be_bytes();
        Ok(TransactionRequest::default()
            .with_input(encode_approve(spender.into(), &amount_word))
            .with_to(self.contract_addrs.token.into()))
    }

    fn transfer<C: Currency>(
        &self,
        destination: Address,
        amount: Balance<C>,
    ) -> payload::Result<Self::TxRequest> {
        let to = if XDai::is::<C>() {
            destination.into()
        } else if WxHOPR::is::<C>() {
            self.contract_addrs.token.into()
        } else {
            return Err(InvalidArguments("invalid currency"));
        };
        Ok(transfer_tx(destination, amount)?.with_to(to))
    }

    fn announce(
        &self,
        announcement: AnnouncementData,
        key_binding_fee: HoprBalance,
    ) -> payload::Result<Self::TxRequest> {
        let call_data = announce_call_data(
            self.me.into(),
            self.contract_addrs.announcements.into(),
            &announcement,
            &key_binding_fee,
        );

        Ok(TransactionRequest::default()
            .with_input(call_data)
            .with_to(self.contract_addrs.token.into()))
    }

    fn fund_channel(&self, dest: Address, amount: HoprBalance) -> payload::Result<Self::TxRequest> {
        if dest.eq(&self.me) {
            return Err(InvalidArguments("Cannot fund channel to self"));
        }
        let amount_word = truncated_word(&amount.amount().to_be_bytes(), 12);
        Ok(TransactionRequest::default()
            .with_input(encode_fund_channel(dest.into(), amount_word))
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
                "Cannot finalize closure of outgoing channel to self",
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
        let balance_word = balance.amount().to_be_bytes();
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

    /// Wraps `call_data` in an `execTransactionFromModule` call to `to`, targeting the Safe module.
    fn module_exec_tx(&self, to: [u8; 20], call_data: &[u8]) -> TransactionRequest {
        TransactionRequest::default()
            .with_input(encode_exec_from_module(to, call_data))
            .with_to(self.module.into())
            .with_gas_limit(DEFAULT_TX_GAS)
    }
}

impl PayloadGenerator for SafePayloadGenerator {
    type TxRequest = TransactionRequest;

    fn approve(&self, spender: Address, amount: HoprBalance) -> payload::Result<Self::TxRequest> {
        let amount_word = amount.amount().to_be_bytes();
        Ok(approve_tx(spender.into(), &amount_word)
            .with_to(self.contract_addrs.token.into())
            .with_gas_limit(DEFAULT_TX_GAS))
    }

    fn transfer<C: Currency>(
        &self,
        destination: Address,
        amount: Balance<C>,
    ) -> payload::Result<Self::TxRequest> {
        let to = if XDai::is::<C>() {
            destination.into()
        } else if WxHOPR::is::<C>() {
            self.contract_addrs.token.into()
        } else {
            return Err(InvalidArguments("invalid currency"));
        };
        Ok(transfer_tx(destination, amount)?
            .with_to(to)
            .with_gas_limit(DEFAULT_TX_GAS))
    }

    fn announce(
        &self,
        announcement: AnnouncementData,
        key_binding_fee: HoprBalance,
    ) -> payload::Result<Self::TxRequest> {
        let call_data = announce_call_data(
            self.me.into(),
            self.contract_addrs.announcements.into(),
            &announcement,
            &key_binding_fee,
        );

        Ok(self.module_exec_tx(self.contract_addrs.token.into(), &call_data))
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
        let amount_word = truncated_word(&amount.amount().to_be_bytes(), 12);
        let call_data = encode_fund_channel_safe(self.me.into(), dest.into(), amount_word);
        Ok(self.module_exec_tx(self.contract_addrs.channels.into(), &call_data))
    }

    fn close_incoming_channel(&self, source: Address) -> payload::Result<Self::TxRequest> {
        if source.eq(&self.me) {
            return Err(InvalidArguments("Cannot close incoming channel from self"));
        }
        let call_data = encode_close_incoming_channel_safe(self.me.into(), source.into());
        Ok(self.module_exec_tx(self.contract_addrs.channels.into(), &call_data))
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
        Ok(self.module_exec_tx(self.contract_addrs.channels.into(), &call_data))
    }

    fn finalize_outgoing_channel_closure(
        &self,
        destination: Address,
    ) -> payload::Result<Self::TxRequest> {
        if destination.eq(&self.me) {
            return Err(InvalidArguments(
                "Cannot finalize closure of outgoing channel to self",
            ));
        }
        let call_data =
            encode_finalize_outgoing_channel_closure_safe(self.me.into(), destination.into());
        Ok(self.module_exec_tx(self.contract_addrs.channels.into(), &call_data))
    }

    fn redeem_ticket(&self, acked_ticket: RedeemableTicket) -> payload::Result<Self::TxRequest> {
        let call_data = encode_redeem_ticket_safe(self.me.into(), &acked_ticket, &self.me)?;
        Ok(self.module_exec_tx(self.contract_addrs.channels.into(), &call_data))
    }

    fn register_safe_by_node(&self, safe_addr: Address) -> payload::Result<Self::TxRequest> {
        Ok(register_safe_tx(safe_addr.into())
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

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use multiaddr::Multiaddr;

    use super::{BasicPayloadGenerator, SafePayloadGenerator};
    use crate::chain::payload::tests::{
        CONTRACT_ADDRS_JSON, PRIVATE_KEY_1, PRIVATE_KEY_2, REDEEMABLE_TICKET,
    };
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
