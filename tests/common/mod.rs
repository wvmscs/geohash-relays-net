// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! Test helpers, from bitchat-console: a local NIP-01 relay and signing keys,
//! a SOCKS5 proxy that records what it is asked, an echo server.
#![allow(dead_code)]

pub mod relay;
pub mod socks;

#[allow(unused_imports)]
pub use relay::{Identity, Sign, TestRelay};
