//! Platform-backed identity stores. No adapter may fall back to a plaintext file.
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod windows;
