# HOPR Types

[![codecov](https://codecov.io/gh/hoprnet/hopr-types/branch/main/graph/badge.svg)](https://codecov.io/gh/hoprnet/hopr-types)

A collection of Rust types used within the HOPR network and related projects.

The exposed types are used in both internal **and** external HOPR APIs.
External APIs may choose to re-export them and externalize them.

External users of the [`hopr-lib`](https://github.com/hoprnet/hoprnet) may not use this crate directly,
but rather rely on the exported types thereby.

## Features

This is a single unified crate with feature-gated modules. Enable the features you need:

| Feature     | Module         | Purpose                                                                               |
| ----------- | -------------- | ------------------------------------------------------------------------------------- |
| `primitive` | `primitive`    | Common primitive types used throughout the entire codebase.                           |
| `random`    | `crypto_random`| Commonly used randomness utilities using a cryptographically secure random generator. |
| `crypto`    | `crypto`       | Implementation of basic cryptographic primitives and related types.                   |
| `internal`  | `internal`     | HOPR-specific types required internally by the HOPR node.                             |
| `chain`     | `chain`        | Core Ethereum-specific types and interactions with the backend database.              |

Use `all-types` to enable all of the above. Features form a dependency chain: `chain` → `internal` → `crypto` → `primitive` + `random`.

## License

This project is licensed under the [GPL-3.0-only](LICENSE).
