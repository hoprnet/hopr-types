# AGENTS.md

Published crate (`hopr-types`) consumed by the other hopr crates and by `edge-client`/`hoprd`.

- Active lines: default (`main`) and `compat/v4`. A merged fix on `main` is not done until it is ported to `compat/v4`; use `/hopr-release`.
- `hopr-types` on `compat/v4` is minor-only: never bump the major there.
- Run cargo through the dev shell: `direnv exec . cargo ...` or `nix develop -c cargo ...`; run `direnv allow` once in a new worktree.
