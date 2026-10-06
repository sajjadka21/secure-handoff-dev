//! Stable X25519 identity material and strict versioned protected-store records.
use std::sync::Arc;

use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const IDENTITY_RECORD_VERSION: u16 = 1;
pub const IDENTITY_RECORD_LEN: usize = 4 + 2 + 32 + 32;
const RECORD_MAGIC: &[u8; 4] = b"CBID";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("secure identity store is unavailable")]
    StoreUnavailable,
    #[error("identity material is missing")]
    Missing,
    #[error("identity material is malformed or has an unsupported version")]
    Malformed,
    #[error("identity public key does not match its private key")]
    KeyMismatch,
    #[error("identity already exists; explicit replacement is required")]
    AlreadyExists,
    #[error("protected identity store operation failed")]
    StoreFailure,
    #[error("protected identity store is locked")]
    StoreLocked,
    #[error("protected identity store denied access or its prompt was dismissed")]
    StorePermissionDenied,
    #[error("protected identity deletion failed")]
    StoreDeletionFailed,
    #[error("operating system error: {0}")]
    OperatingSystem(u32),
}

/// The secret is held in a zeroizing wrapper; copies made by crypto backends are best effort.
pub struct DeviceIdentity {
    private_key: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
}

impl DeviceIdentity {
    pub fn generate() -> Result<Self, IdentityError> {
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::fill(secret.as_mut()).map_err(|_| IdentityError::StoreUnavailable)?;
        Self::from_private(*secret)
    }

    pub fn from_private(secret: [u8; 32]) -> Result<Self, IdentityError> {
        let private_key = Zeroizing::new(secret);
        let static_secret = StaticSecret::from(*private_key);
        let public_key = *PublicKey::from(&static_secret).as_bytes();
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn from_record(record: &[u8]) -> Result<Self, IdentityError> {
        if record.len() != IDENTITY_RECORD_LEN || &record[..4] != RECORD_MAGIC {
            return Err(IdentityError::Malformed);
        }
        if u16::from_be_bytes([record[4], record[5]]) != IDENTITY_RECORD_VERSION {
            return Err(IdentityError::Malformed);
        }
        let private: [u8; 32] = record[6..38]
            .try_into()
            .map_err(|_| IdentityError::Malformed)?;
        let stored_public: [u8; 32] = record[38..70]
            .try_into()
            .map_err(|_| IdentityError::Malformed)?;
        let identity = Self::from_private(private)?;
        if identity.public_key != stored_public {
            return Err(IdentityError::KeyMismatch);
        }
        Ok(identity)
    }

    pub fn to_record(&self) -> [u8; IDENTITY_RECORD_LEN] {
        let mut record = [0; IDENTITY_RECORD_LEN];
        record[..4].copy_from_slice(RECORD_MAGIC);
        record[4..6].copy_from_slice(&IDENTITY_RECORD_VERSION.to_be_bytes());
        record[6..38].copy_from_slice(self.private_key.as_ref());
        record[38..70].copy_from_slice(&self.public_key);
        record
    }

    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    pub fn device_id(&self) -> [u8; 32] {
        *blake3::hash(&self.public_key).as_bytes()
    }
    pub fn fingerprint(&self) -> String {
        hex_encode(&self.device_id())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

/// Platform adapters store only `DeviceIdentity::to_record()` in protected storage.
pub trait IdentityStore: Send + Sync {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError>;
    fn write(&self, record: &[u8]) -> Result<(), IdentityError>;
    fn delete(&self) -> Result<(), IdentityError>;
}

pub struct IdentityManager<S: IdentityStore> {
    store: Arc<S>,
}
impl<S: IdentityStore> IdentityManager<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }
    /// Explicit first-run creation. A missing record during ordinary startup is an error.
    pub fn create_new(&self) -> Result<DeviceIdentity, IdentityError> {
        if self.store.read()?.is_some() {
            return Err(IdentityError::AlreadyExists);
        }
        let identity = DeviceIdentity::generate()?;
        self.store.write(&identity.to_record())?;
        Ok(identity)
    }
    pub fn load_existing(&self) -> Result<DeviceIdentity, IdentityError> {
        DeviceIdentity::from_record(&self.store.read()?.ok_or(IdentityError::Missing)?)
    }
    /// Deliberately named explicit operation. Callers must revoke peers and require fresh pairing.
    pub fn replace_identity_explicit(&self) -> Result<DeviceIdentity, IdentityError> {
        let identity = DeviceIdentity::generate()?;
        self.store.write(&identity.to_record())?;
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemoryStore(Mutex<Option<Zeroizing<Vec<u8>>>>);
    impl IdentityStore for MemoryStore {
        fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .as_ref()
                .map(|v| Zeroizing::new(v.to_vec())))
        }
        fn write(&self, record: &[u8]) -> Result<(), IdentityError> {
            *self.0.lock().unwrap() = Some(Zeroizing::new(record.to_vec()));
            Ok(())
        }
        fn delete(&self) -> Result<(), IdentityError> {
            self.0.lock().unwrap().take();
            Ok(())
        }
    }

    #[test]
    fn identity_record_round_trips_and_is_stable() {
        let id = DeviceIdentity::from_private([9; 32]).unwrap();
        let decoded = DeviceIdentity::from_record(&id.to_record()).unwrap();
        assert_eq!(id.public_key(), decoded.public_key());
        assert_eq!(id.device_id(), decoded.device_id());
    }
    #[test]
    fn rejects_corruption_mismatch_and_wrong_lengths() {
        let id = DeviceIdentity::from_private([8; 32]).unwrap();
        let mut mismatch = id.to_record();
        mismatch[38] ^= 1;
        assert!(matches!(
            DeviceIdentity::from_record(&mismatch),
            Err(IdentityError::KeyMismatch)
        ));
        assert!(matches!(
            DeviceIdentity::from_record(&id.to_record()[..69]),
            Err(IdentityError::Malformed)
        ));
        let mut version = id.to_record();
        version[5] = 2;
        assert!(matches!(
            DeviceIdentity::from_record(&version),
            Err(IdentityError::Malformed)
        ));
    }

    #[test]
    fn persistent_manager_never_regenerates_corrupt_or_missing_identity() {
        let store = Arc::new(MemoryStore::default());
        let manager = IdentityManager::new(store.clone());
        assert!(matches!(
            manager.load_existing(),
            Err(IdentityError::Missing)
        ));
        let first = manager.create_new().unwrap();
        assert!(matches!(
            manager.create_new(),
            Err(IdentityError::AlreadyExists)
        ));
        let reloaded = manager.load_existing().unwrap();
        assert_eq!(first.device_id(), reloaded.device_id());
        let replacement = manager.replace_identity_explicit().unwrap();
        assert_ne!(first.device_id(), replacement.device_id());
        store.0.lock().unwrap().as_mut().unwrap()[0] ^= 1;
        assert!(matches!(
            manager.load_existing(),
            Err(IdentityError::Malformed)
        ));
    }
}
