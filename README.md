# HOPR Types

A collection of Rust types used within the HOPR network and related projects.

The exposed types are used in both internal **and** external HOPR APIs.
External APIs may choose to re-export them and externalize them.

External users of the [`hopr-lib`](https://github.com/hoprnet/hoprnet) may not use this crate directly,
but rather rely on the exported types thereby.

## Sub-crates

This workspace contains several crates, each serving a specific purpose. The crates
should not be used independently, but always through the main crate `hopr-types` by enabling respective feature(s).

| Sub-Crate                | `hopr-types` feature | Purpose                                                                               |
| ------------------------ | -------------------- | ------------------------------------------------------------------------------------- |
| **hopr-chain-types**     | `chain`              | Core Ethereum-specific types and interactions with the backend database.              |
| **hopr-crypto-types**    | `crypto`             | Implementation of basic cryptographic primitives and related types.                   |
| **hopr-crypto-random**   | `random`             | Commonly used randomness utilities using a cryptographically secure random generator. |
| **hopr-internal-types**  | `internal`           | HOPR-specific types required internally by the HOPR node.                             |
| **hopr-primitive-types** | `primitive`          | Common primitive types used throughout the entire codebase.                           |
| **hopr-parallelize**     | `parallelize`        | Utilities and types for parallel execution and concurrency.                           |

## License

This project is licensed under the [GPL-3.0-only](LICENSE).
