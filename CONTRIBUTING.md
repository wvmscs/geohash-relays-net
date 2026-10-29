# Contributing

Issues and pull requests are welcome. Code, comments and documentation are in English.

## Before a pull request

```sh
cargo fmt --check
for f in bitchat bitchat-android console; do
  cargo clippy --all-targets --features $f -- -D warnings
  cargo test --features $f
done
cargo deny --features console,arti check advisories licenses sources
reuse lint
```

The CI runs the same checks on every pull request.

## Rules

- **Branch:** open the pull request against `main`, **rebased** on its latest commit
  (no merge commits). Rebase again when `main` moves.
- **Licence:** contributions are accepted under the licence of the project (GPL-3.0-or-later).
  Every new file starts with its SPDX tags (`SPDX-FileCopyrightText`,
  `SPDX-License-Identifier`), or is covered by `REUSE.toml`.
- **Dependencies:** a new dependency must pass `cargo deny` (licence compatible with
  GPL-3.0-or-later).
- **Tests are offline** and reproducible: local test relays and proxies, frozen data. Never
  publish on public relays or real channels from a test. The tests that use the real network
  are `#[ignore]`d and need you to name your own relay in an environment variable.
- **No personal data** in issues, logs or test data: no seed, key, private message or real
  pubkey. Redact logs before you paste them.
- See `AGENTS.md` for the design rules of the project.

## Security

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).
