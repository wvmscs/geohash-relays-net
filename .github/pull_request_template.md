## What and why

## Checks

- [ ] Rebased on the latest `main`, no merge commit
- [ ] `cargo fmt --check`, clippy and tests with each feature (`bitchat`, `bitchat-android`, `console`)
- [ ] `cargo deny check advisories licenses sources`, `reuse lint`
- [ ] Tests offline; no seed, key, private message or real pubkey in the diff
- [ ] CHANGELOG updated if the behaviour changes
