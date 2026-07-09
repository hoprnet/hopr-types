use std::{hint::black_box, str::FromStr, time::Duration};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use hex_literal::hex;
use hopr_types::{
    chain::prelude::{BasicPayloadGenerator, PayloadGenerator, SafePayloadGenerator},
    crypto::prelude::{ChainKeypair, Keypair, OffchainKeypair, OffchainSignature, PublicKey},
    internal::prelude::{AnnouncementData, KeyBinding},
    primitive::prelude::{Address, HoprBalance, ToHex},
};
use multiaddr::Multiaddr;

const CONTRACT_ADDRS_JSON: &str = r#"{
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

const PRIVATE_KEY_1: [u8; 32] =
    hex!("c14b8faa0a9b8a5fa4453664996f23a7e7de606d42297d723fc4a794f375e260");
const PUBLIC_KEY_UNCOMPRESSED_PLAIN: [u8; 64] = hex!(
    "1464586aeaea0eb5736884ca1bf42d165fc8e2243b1d917130fb9e321d7a93b8fb0699d4f177f9c84712f6d7c5f6b7f4f6916116047fa25c79ef806fc6c9523e"
);
const ADDRESS_SIZE: usize = 20;

fn configure(c: &mut Criterion) -> criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> {
    let mut group = c.benchmark_group("memory_allocation_bench");
    group.sample_size(80);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    group
}

fn memory_allocation_bench(c: &mut Criterion) {
    let mut group = configure(c);

    let address_hex = "0x52908400098527886e0f7030069857d2e4169ee7";
    group.bench_function("address_from_hex_stack", |b| {
        b.iter(|| Address::from_str(black_box(address_hex)).unwrap())
    });

    let address = Address::from_str(address_hex).unwrap();
    group.bench_function("address_to_checksum", |b| {
        b.iter(|| black_box(address).to_checksum())
    });

    let sig = OffchainSignature::sign_message(b"benchmark-message", &OffchainKeypair::random());
    let sig_hex = sig.to_hex();
    group.bench_function("offchain_signature_from_hex_stack", |b| {
        b.iter(|| OffchainSignature::from_hex(black_box(&sig_hex)).unwrap())
    });

    group.bench_function("public_key_from_uncompressed_plain", |b| {
        b.iter(|| PublicKey::try_from(black_box(PUBLIC_KEY_UNCOMPRESSED_PLAIN.as_ref())).unwrap())
    });

    const BATCH_SIZE: usize = 100;
    let batch = (0..BATCH_SIZE)
        .map(|i| {
            let keypair = OffchainKeypair::random();
            let msg =
                hopr_types::crypto::types::Hash::create(&[format!("test_msg_{i}").as_bytes()]);
            let sig = OffchainSignature::sign_message(msg.as_ref(), &keypair);
            Some(((msg, sig), *keypair.public()))
        })
        .collect::<Vec<_>>();

    group.bench_function("offchain_signature_verify_batch_filter_map", |b| {
        b.iter(|| {
            OffchainSignature::verify_batch(black_box(batch.iter()).filter_map(|entry| *entry))
        })
    });

    let contract_addrs = serde_json::from_str(CONTRACT_ADDRS_JSON).unwrap();
    let chain_key = ChainKeypair::from_secret(&PRIVATE_KEY_1).unwrap();
    let basic_generator = BasicPayloadGenerator::new((&chain_key).into(), contract_addrs);
    let safe_generator = SafePayloadGenerator::new(
        &chain_key,
        contract_addrs,
        Address::from([1u8; ADDRESS_SIZE]),
    );
    let key_binding = KeyBinding::new(
        (&chain_key).into(),
        &OffchainKeypair::from_secret(&PRIVATE_KEY_1).unwrap(),
    );
    let multiaddr = Multiaddr::from_str("/ip4/1.2.3.4/tcp/56").unwrap();
    let announcement = AnnouncementData::new(key_binding, Some(multiaddr)).unwrap();

    group.bench_function("bindings_announce_basic_payload", |b| {
        b.iter_batched(
            || announcement.clone(),
            |announcement| {
                basic_generator
                    .announce(
                        black_box(announcement),
                        black_box(HoprBalance::from(100_u32)),
                    )
                    .unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("bindings_announce_safe_payload", |b| {
        b.iter_batched(
            || announcement.clone(),
            |announcement| {
                safe_generator
                    .announce(
                        black_box(announcement),
                        black_box(HoprBalance::from(100_u32)),
                    )
                    .unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    let admins: Vec<Address> = vec![
        Address::from([0x22; ADDRESS_SIZE]),
        Address::from([0x33; ADDRESS_SIZE]),
    ];
    group.bench_function("bindings_deploy_safe_payload", |b| {
        b.iter(|| {
            basic_generator
                .deploy_safe(
                    black_box(HoprBalance::from(1000_u32)),
                    black_box(&admins),
                    black_box(true),
                    black_box([0x44u8; 32]),
                )
                .unwrap()
        })
    });

    group.finish();
}

criterion_group!(benches, memory_allocation_bench);
criterion_main!(benches);
