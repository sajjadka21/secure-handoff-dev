//! Narrow Android JNI boundary. Cryptographic formats and identity validation live in clipcore.
use clipcore::identity::DeviceIdentity;
use jni::{
    JNIEnv,
    objects::{JByteArray, JClass},
    sys::jbyteArray,
};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

static ANDROID_IDENTITY: OnceLock<Mutex<Option<DeviceIdentity>>> = OnceLock::new();

/// Return public metadata only: device ID followed by the 32-byte static public key.
fn public_metadata(record: &[u8]) -> Result<[u8; 64], clipcore::identity::IdentityError> {
    let identity = DeviceIdentity::from_record(record)?;
    let mut result = [0; 64];
    result[..32].copy_from_slice(&identity.device_id());
    result[32..].copy_from_slice(identity.public_key());
    Ok(result)
}

fn install_identity(
    record: &[u8],
    current: &mut Option<DeviceIdentity>,
) -> Result<[u8; 64], clipcore::identity::IdentityError> {
    let identity = DeviceIdentity::from_record(record)?;
    let mut metadata = [0; 64];
    metadata[..32].copy_from_slice(&identity.device_id());
    metadata[32..].copy_from_slice(identity.public_key());
    match current.as_ref() {
        Some(existing) if existing.device_id() == identity.device_id() => {}
        Some(_) => return Err(clipcore::identity::IdentityError::AlreadyExists),
        None => *current = Some(identity),
    }
    Ok(metadata)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeGenerateIdentityRecord(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jbyteArray {
    let Ok(identity) = DeviceIdentity::generate() else {
        return std::ptr::null_mut();
    };
    let record = Zeroizing::new(identity.to_record());
    env.byte_array_from_slice(&record[..])
        .map_or(std::ptr::null_mut(), |array| array.into_raw())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeIdentityMetadata(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    record: JByteArray<'_>,
) -> jbyteArray {
    let Ok(record) = env.convert_byte_array(&record).map(Zeroizing::new) else {
        return std::ptr::null_mut();
    };
    let Ok(metadata) = public_metadata(&record) else {
        return std::ptr::null_mut();
    };
    env.byte_array_from_slice(&metadata)
        .map_or(std::ptr::null_mut(), |array| array.into_raw())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeInstallIdentityRecord(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    record: JByteArray<'_>,
) -> jbyteArray {
    let Ok(record) = env.convert_byte_array(&record).map(Zeroizing::new) else {
        return std::ptr::null_mut();
    };
    let identity = ANDROID_IDENTITY.get_or_init(|| Mutex::new(None));
    let Ok(mut current) = identity.lock() else {
        return std::ptr::null_mut();
    };
    let Ok(metadata) = install_identity(&record, &mut current) else {
        return std::ptr::null_mut();
    };
    env.byte_array_from_slice(&metadata)
        .map_or(std::ptr::null_mut(), |array| array.into_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_stable_and_contains_only_public_values() {
        let identity = DeviceIdentity::generate().unwrap();
        let record = identity.to_record();
        let first = public_metadata(&record).unwrap();
        let second = public_metadata(&record).unwrap();
        assert_eq!(first, second);
        assert_eq!(&first[..32], &identity.device_id());
        assert_eq!(&first[32..], identity.public_key());
        assert_ne!(&first[..32], &record[6..38]);
    }

    #[test]
    fn malformed_and_mismatched_records_fail_closed() {
        let identity = DeviceIdentity::generate().unwrap();
        let mut record = identity.to_record();
        record[40] ^= 0x80;
        assert!(public_metadata(&record).is_err());
        assert!(public_metadata(&record[..69]).is_err());
    }

    #[test]
    fn identity_install_does_not_silently_replace_a_live_identity() {
        let first = DeviceIdentity::generate().unwrap();
        let second = DeviceIdentity::generate().unwrap();
        let first_record = first.to_record();
        let second_record = second.to_record();
        let mut slot = None;
        assert!(install_identity(&first_record, &mut slot).is_ok());
        assert!(install_identity(&first_record, &mut slot).is_ok());
        assert!(matches!(
            install_identity(&second_record, &mut slot),
            Err(clipcore::identity::IdentityError::AlreadyExists)
        ));
    }
}

