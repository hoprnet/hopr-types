use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use hopr_types::{
    crypto::{
        keypairs::Keypair,
        prelude::{OffchainKeypair, OffchainPublicKey},
        primitives::Curve25519CompressedPoint,
    },
    primitive::traits::BytesRepresentable,
};
use libp2p_identity::PeerId;

// Avoid musl's default allocator due to degraded performance
//
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(all(feature = "allocator-mimalloc", feature = "allocator-jemalloc"))]
compile_error!(
    "feature \"allocator-jemalloc\" and feature \"allocator-mimalloc\" cannot be enabled at the same time"
);
#[cfg(all(target_os = "linux", feature = "allocator-mimalloc"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
#[cfg(all(target_os = "linux", feature = "allocator-jemalloc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const SAMPLE_SIZE: usize = 100_000;

pub fn offchain_public_key_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("offchain_public_key_bench");
    group.sample_size(SAMPLE_SIZE);
    group.throughput(Throughput::Elements(1));

    group.bench_function("offchain_public_key_from_peer_id", |b| {
        let peer_id = PeerId::from(OffchainKeypair::random().public());
        b.iter(|| OffchainPublicKey::from_peerid(&peer_id))
    });

    // Runs on every outbound packet, forwarded packet and acknowledgement, because the libp2p
    // sink is addressed by `PeerId`. See `hoprnet:transport/hopr/src/protocol/pipeline/mod.rs`.
    group.bench_function("offchain_public_key_to_peer_id", |b| {
        let key = *OffchainKeypair::random().public();
        b.iter(|| PeerId::from(black_box(&key)))
    });

    // The parse path taken by every key read out of the chain indexer, the DB or a hex string.
    group.bench_function("offchain_public_key_from_bytes", |b| {
        let bytes: [u8; OffchainPublicKey::SIZE] = (*OffchainKeypair::random().public()).into();
        b.iter(|| OffchainPublicKey::try_from(black_box(bytes.as_slice())))
    });

    // Bare Ed25519 point decompression: the cost that an expanded-vs-compact key split moves
    // from parse time to the Sphinx sender path. Measured directly against `curve25519-dalek`
    // so that the number exists before the type does.
    group.bench_function("offchain_public_key_expand", |b| {
        let compressed =
            Curve25519CompressedPoint::from_slice(OffchainKeypair::random().public().as_ref())
                .expect("public key is always 32 bytes");
        b.iter(|| black_box(&compressed).decompress())
    });

    group.finish();
}

criterion_group!(benches, offchain_public_key_bench);
criterion_main!(benches);
