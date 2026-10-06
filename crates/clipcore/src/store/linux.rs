//! freedesktop Secret Service adapter. The secret is the only location holding identity bytes.
use crate::identity::{DeviceIdentity, IdentityError, IdentityStore};
use secret_service::{EncryptionType, SecretService};
use std::collections::HashMap;
use zeroize::Zeroizing;

const ATTRIBUTES: [(&str, &str); 3] = [
    ("application", "org.clipbridge.identity"),
    ("schema", "identity-v1"),
    ("slot", "device-static"),
];
const ITEM_LABEL: &str = "ClipBridge device identity";

pub struct LinuxSecretServiceStore;
impl LinuxSecretServiceStore {
    fn map_error(error: secret_service::Error) -> IdentityError {
        match error {
            secret_service::Error::Locked => IdentityError::StoreLocked,
            secret_service::Error::Prompt => IdentityError::StorePermissionDenied,
            secret_service::Error::Unavailable => IdentityError::StoreUnavailable,
            _ => IdentityError::StoreFailure,
        }
    }
    fn run<T>(
        f: impl for<'a> FnOnce(&'a tokio::runtime::Runtime) -> Result<T, IdentityError>,
    ) -> Result<T, IdentityError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| IdentityError::StoreUnavailable)?;
        f(&runtime)
    }
    async fn connection() -> Result<SecretService<'static>, IdentityError> {
        SecretService::connect(EncryptionType::Dh)
            .await
            .map_err(Self::map_error)
    }
    fn attributes() -> HashMap<&'static str, &'static str> {
        ATTRIBUTES.into_iter().collect()
    }
}
impl IdentityStore for LinuxSecretServiceStore {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Self::run(|rt| {
            rt.block_on(async {
                let service = Self::connection().await?;
                let found = service
                    .search_items(Self::attributes())
                    .await
                    .map_err(Self::map_error)?;
                if found.unlocked.len() + found.locked.len() > 1 {
                    return Err(IdentityError::Malformed);
                }
                let item = if let Some(item) = found.unlocked.first() {
                    item
                } else if let Some(item) = found.locked.first() {
                    item.unlock().await.map_err(Self::map_error)?;
                    item
                } else {
                    return Ok(None);
                };
                let secret = Zeroizing::new(item.get_secret().await.map_err(Self::map_error)?);
                DeviceIdentity::from_record(&secret)?;
                Ok(Some(secret))
            })
        })
    }
    fn write(&self, record: &[u8]) -> Result<(), IdentityError> {
        DeviceIdentity::from_record(record)?;
        let secret = Zeroizing::new(record.to_vec());
        Self::run(|rt| {
            rt.block_on(async {
                let service = Self::connection().await?;
                let collection = service
                    .get_default_collection()
                    .await
                    .map_err(Self::map_error)?;
                collection
                    .ensure_unlocked()
                    .await
                    .map_err(Self::map_error)?;
                let matches = service
                    .search_items(Self::attributes())
                    .await
                    .map_err(Self::map_error)?;
                if matches.unlocked.len() + matches.locked.len() > 1 {
                    return Err(IdentityError::Malformed);
                }
                let attributes = Self::attributes();
                collection
                    .create_item(
                        ITEM_LABEL,
                        attributes,
                        &secret,
                        true,
                        "application/octet-stream",
                    )
                    .await
                    .map_err(|_| IdentityError::StoreFailure)?;
                Ok(())
            })
        })
    }
    fn delete(&self) -> Result<(), IdentityError> {
        Self::run(|rt| {
            rt.block_on(async {
                let service = Self::connection().await?;
                let found = service
                    .search_items(Self::attributes())
                    .await
                    .map_err(Self::map_error)?;
                if found.unlocked.len() + found.locked.len() > 1 {
                    return Err(IdentityError::Malformed);
                }
                if let Some(item) = found.unlocked.first() {
                    item.delete()
                        .await
                        .map_err(|_| IdentityError::StoreDeletionFailed)?;
                    return Ok(());
                }
                if let Some(item) = found.locked.first() {
                    item.unlock().await.map_err(Self::map_error)?;
                    item.delete()
                        .await
                        .map_err(|_| IdentityError::StoreDeletionFailed)?;
                    return Ok(());
                }
                Err(IdentityError::Missing)
            })
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_lookup_metadata_is_constant_non_identifying_schema_only() {
        assert_eq!(ATTRIBUTES.len(), 3);
        for (key, value) in ATTRIBUTES {
            assert!(!key.contains("device"));
            assert!(!value.contains("fingerprint"));
        }
    }

    #[test]
    fn service_locked_prompt_and_unavailable_errors_fail_closed() {
        assert!(matches!(
            LinuxSecretServiceStore::map_error(secret_service::Error::Locked),
            IdentityError::StoreLocked
        ));
        assert!(matches!(
            LinuxSecretServiceStore::map_error(secret_service::Error::Prompt),
            IdentityError::StorePermissionDenied
        ));
        assert!(matches!(
            LinuxSecretServiceStore::map_error(secret_service::Error::Unavailable),
            IdentityError::StoreUnavailable
        ));
    }

    #[test]
    #[ignore = "requires an isolated, disposable Secret Service session"]
    fn secret_service_real_backend_round_trip_in_isolated_session() {
        let store = LinuxSecretServiceStore;
        assert!(
            store.read().unwrap().is_none(),
            "refusing to overwrite an existing identity"
        );

        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = LinuxSecretServiceStore.delete();
            }
        }

        let _cleanup = Cleanup;
        let identity = DeviceIdentity::generate().unwrap();
        let record = identity.to_record();
        store.write(&record).unwrap();
        let loaded = store.read().unwrap().unwrap();
        assert_eq!(&*loaded, record.as_slice());
        store.delete().unwrap();
        assert!(store.read().unwrap().is_none());
    }
}
