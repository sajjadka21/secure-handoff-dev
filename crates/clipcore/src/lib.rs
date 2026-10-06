//! Shared protocol core. Phase 1 intentionally contains no OS clipboard or key-store adapter.
pub mod identity;
pub mod pairing;
pub mod protocol;
pub mod qr;
pub mod session;
pub mod store;
pub mod transport;
pub mod trust;

pub const CURRENT_PROTOCOL_VERSION: u16 = 1;
// Noise's 65,535-byte record ceiling minus the envelope header and AEAD tag.
pub const MAX_TEXT_BYTES: usize = 65_484;
