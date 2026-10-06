//! Windows Credential Manager generic credential adapter (`CRED_PERSIST_LOCAL_MACHINE`).
use crate::identity::{DeviceIdentity, IDENTITY_RECORD_LEN, IdentityError, IdentityStore};
use std::ptr::null_mut;
use windows_sys::Win32::{
    Foundation::{ERROR_NOT_FOUND, GetLastError},
    Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree,
        CredReadW, CredWriteW,
    },
};
use zeroize::Zeroizing;

const TARGET: &[u16] = &[
    67, 108, 105, 112, 66, 114, 105, 100, 103, 101, 46, 73, 100, 101, 110, 116, 105, 116, 121, 46,
    118, 49, 0,
];

pub struct WindowsCredentialStore;
impl IdentityStore for WindowsCredentialStore {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        let mut raw: *mut CREDENTIALW = null_mut();
        // SAFETY: target is a static NUL-terminated UTF-16 string; output is freed by CredFree.
        let ok = unsafe { CredReadW(TARGET.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) };
        if ok == 0 {
            // SAFETY: GetLastError has no pointer arguments.
            let error = unsafe { GetLastError() };
            return if error == ERROR_NOT_FOUND {
                Ok(None)
            } else {
                Err(IdentityError::OperatingSystem(error))
            };
        }
        if raw.is_null() {
            return Err(IdentityError::StoreFailure);
        }
        struct CredGuard(*mut CREDENTIALW);
        impl Drop for CredGuard {
            fn drop(&mut self) {
                unsafe { CredFree(self.0.cast()) }
            }
        }
        let guard = CredGuard(raw);
        // SAFETY: successful CredReadW provides a valid structure until CredFree.
        let record = Zeroizing::new(unsafe {
            let cred = &*guard.0;
            if cred.CredentialBlobSize as usize != IDENTITY_RECORD_LEN
                || cred.CredentialBlob.is_null()
            {
                return Err(IdentityError::Malformed);
            }
            std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize)
                .to_vec()
        });
        DeviceIdentity::from_record(&record)?;
        Ok(Some(record))
    }
    fn write(&self, record: &[u8]) -> Result<(), IdentityError> {
        DeviceIdentity::from_record(record)?;
        let mut record = Zeroizing::new(record.to_vec());
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: TARGET.as_ptr() as *mut u16,
            CredentialBlobSize: u32::try_from(record.len())
                .map_err(|_| IdentityError::Malformed)?,
            CredentialBlob: record.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        };
        // SAFETY: all pointers remain valid for the duration of the synchronous call.
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            return Err(IdentityError::OperatingSystem(unsafe { GetLastError() }));
        }
        Ok(())
    }
    fn delete(&self) -> Result<(), IdentityError> {
        // SAFETY: target is a static NUL-terminated UTF-16 string.
        if unsafe { CredDeleteW(TARGET.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
            return Ok(());
        }
        Err(IdentityError::OperatingSystem(unsafe { GetLastError() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_target_is_fixed_and_machine_local_is_explicit() {
        assert_eq!(CRED_PERSIST_LOCAL_MACHINE, 2);
        assert_eq!(TARGET.last(), Some(&0));
    }

    #[test]
    fn credential_blob_requires_exact_versioned_identity_record() {
        let identity = DeviceIdentity::from_private([0x42; 32]).unwrap();
        let record = identity.to_record();
        assert_eq!(record.len(), IDENTITY_RECORD_LEN);
        assert!(DeviceIdentity::from_record(&record).is_ok());
        assert!(DeviceIdentity::from_record(&record[..record.len() - 1]).is_err());
    }
}
