//! Narrow Android JNI boundary. Cryptographic formats and identity validation live in clipcore.
use clipcore::identity::DeviceIdentity;
use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JString},
    sys::{jboolean, jbyteArray, jstring},
};
use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;

static ANDROID_IDENTITY: OnceLock<Mutex<Option<DeviceIdentity>>> = OnceLock::new();
static TRUST_DB: OnceLock<Mutex<Option<Arc<clipcore::trust::TrustDb>>>> = OnceLock::new();
static PENDING_PAIRING: OnceLock<Mutex<Option<PendingPairing>>> = OnceLock::new();
static LAN_LISTENER: OnceLock<Mutex<Option<TcpListener>>> = OnceLock::new();
static PRIVACY_PAUSED: AtomicBool = AtomicBool::new(false);

struct PendingPairing {
    stream: TcpStream,
    handshake: clipcore::session::PairingHandshake,
    transaction: clipcore::pairing::PairingTransaction,
}

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

fn utf8_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Result<String, jni::errors::Error> {
    env.get_string(value).map(|value| value.into())
}

fn with_trust<T>(
    f: impl FnOnce(&clipcore::trust::TrustDb) -> Result<T, clipcore::trust::TrustError>,
) -> Result<T, clipcore::trust::TrustError> {
    let db = TRUST_DB.get_or_init(|| Mutex::new(None));
    let guard = db
        .lock()
        .map_err(|_| clipcore::trust::TrustError::InvalidIdentity)?;
    let db = guard
        .as_deref()
        .ok_or(clipcore::trust::TrustError::InvalidIdentity)?;
    f(db)
}

fn trust_db_arc() -> Option<Arc<clipcore::trust::TrustDb>> {
    TRUST_DB.get()?.lock().ok()?.as_ref().cloned()
}

fn decode_32(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

fn is_allowed_lan_bind(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(value) => value.is_private() || value.is_loopback(),
        std::net::IpAddr::V6(value) => {
            value.is_loopback() || (value.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeGenerateIdentityRecord(
    env: JNIEnv<'_>,
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeOpenTrustDb(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    path: JString<'_>,
) -> jboolean {
    let Ok(path) = utf8_string(&mut env, &path) else {
        return 0;
    };
    if path.is_empty() || path.len() > 4096 {
        return 0;
    }
    let Ok(db) = clipcore::trust::TrustDb::open(path) else {
        return 0;
    };
    let slot = TRUST_DB.get_or_init(|| Mutex::new(None));
    match slot.lock() {
        Ok(mut current) => {
            *current = Some(Arc::new(db));
            1
        }
        Err(_) => 0,
    }
}

/// Encodes public trust metadata only: count, then device id, public key, label length/UTF-8,
/// protocol floor, timestamp, and a one-byte trusted/needs-repair state.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeListTrustedDevices(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jbyteArray {
    let Ok(devices) = with_trust(|db| db.list_devices()) else {
        return std::ptr::null_mut();
    };
    if devices.len() > 256 {
        return std::ptr::null_mut();
    }
    let mut out = Vec::with_capacity(4 + devices.len() * 110);
    out.extend_from_slice(&(devices.len() as u32).to_be_bytes());
    for device in devices {
        let label = device.label.as_bytes();
        if label.len() > 64 {
            return std::ptr::null_mut();
        }
        out.extend_from_slice(&device.device_id);
        out.extend_from_slice(&device.public_key);
        out.extend_from_slice(&(label.len() as u16).to_be_bytes());
        out.extend_from_slice(label);
        out.extend_from_slice(&device.minimum_protocol.to_be_bytes());
        out.extend_from_slice(&device.trusted_at.to_be_bytes());
        out.push(match device.status {
            clipcore::trust::TrustStatus::Trusted => 1,
            clipcore::trust::TrustStatus::NeedsRepair => 2,
        });
    }
    env.byte_array_from_slice(&out)
        .map_or(std::ptr::null_mut(), |v| v.into_raw())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeSetPrivacyPaused(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    paused: jboolean,
) {
    PRIVACY_PAUSED.store(paused != 0, Ordering::Release);
    if paused != 0
        && let Some(pending) = PENDING_PAIRING
            .get()
            .and_then(|slot| slot.lock().ok()?.take())
    {
        drop(pending);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeJoinPairing(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    payload: JByteArray<'_>,
    label: JString<'_>,
) -> jstring {
    if PRIVACY_PAUSED.load(Ordering::Acquire) {
        return std::ptr::null_mut();
    }
    let Ok(payload) = env.convert_byte_array(&payload).map(Zeroizing::new) else {
        return std::ptr::null_mut();
    };
    if payload.len() > clipcore::qr::QR_MAX_BYTES {
        return std::ptr::null_mut();
    }
    let Ok(qr) = clipcore::qr::PairingQr::decode(payload.as_slice()) else {
        return std::ptr::null_mut();
    };
    let Ok(label) = utf8_string(&mut env, &label) else {
        return std::ptr::null_mut();
    };
    let label = label.trim();
    if label.is_empty() || label.len() > 64 || label.chars().any(char::is_control) {
        return std::ptr::null_mut();
    }
    let Some(endpoint) = qr
        .endpoints
        .first()
        .and_then(|v| v.parse::<SocketAddr>().ok())
    else {
        return std::ptr::null_mut();
    };
    let Some(identity_record) = ANDROID_IDENTITY.get().and_then(|slot| {
        slot.lock()
            .ok()?
            .as_ref()
            .map(|v| Zeroizing::new(v.to_record()))
    }) else {
        return std::ptr::null_mut();
    };
    let Ok(identity) = DeviceIdentity::from_record(identity_record.as_ref()) else {
        return std::ptr::null_mut();
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&endpoint, Duration::from_secs(8)) else {
        return std::ptr::null_mut();
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .is_err()
        || stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .is_err()
    {
        return std::ptr::null_mut();
    }
    let Ok(handshake) = clipcore::session::establish_pairing(
        &mut stream,
        &identity,
        &qr,
        true,
        clipcore::CURRENT_PROTOCOL_VERSION,
    ) else {
        return std::ptr::null_mut();
    };
    if PRIVACY_PAUSED.load(Ordering::Acquire) {
        return std::ptr::null_mut();
    }
    let transaction = clipcore::pairing::PairingTransaction::from_verified_handshake(
        &identity,
        &handshake,
        label.to_owned(),
    );
    let view = format!("{}\t{}", transaction.sas(), hex(transaction.peer_id()));
    let slot = PENDING_PAIRING.get_or_init(|| Mutex::new(None));
    let Ok(mut pending) = slot.lock() else {
        return std::ptr::null_mut();
    };
    *pending = Some(PendingPairing {
        stream,
        handshake,
        transaction,
    });
    env.new_string(view)
        .map_or(std::ptr::null_mut(), |v| v.into_raw())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeConfirmPairing(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    accepted: jboolean,
) -> jstring {
    let finish = || -> Result<&'static str, &'static str> {
        if PRIVACY_PAUSED.load(Ordering::Acquire) {
            return Err("privacy_paused");
        }
        let slot = PENDING_PAIRING.get_or_init(|| Mutex::new(None));
        let mut pending = slot
            .lock()
            .map_err(|_| "pairing_state_error")?
            .take()
            .ok_or("pairing_not_ready")?;
        if accepted == 0 {
            let _ = pending.transaction.confirm_local(false);
            return Ok("rejected");
        }
        let result = (|| {
            let confirm = pending
                .transaction
                .confirm_local(true)
                .map_err(|_| "pairing_incomplete")?;
            clipcore::session::send_pair_control(
                &mut pending.stream,
                pending.handshake.transport_mut(),
                &confirm,
                0,
            )
            .map_err(|_| "pairing_incomplete")?;
            let peer_confirm = clipcore::session::receive_pair_control(
                &mut pending.stream,
                pending.handshake.transport_mut(),
                0,
            )
            .map_err(|_| "pairing_incomplete")?;
            pending
                .transaction
                .receive_confirm(&peer_confirm)
                .map_err(|_| "pairing_incomplete")?;
            let ack = pending
                .transaction
                .make_ack()
                .map_err(|_| "pairing_incomplete")?;
            clipcore::session::send_pair_control(
                &mut pending.stream,
                pending.handshake.transport_mut(),
                &ack,
                1,
            )
            .map_err(|_| "pairing_incomplete")?;
            let peer_ack = clipcore::session::receive_pair_control(
                &mut pending.stream,
                pending.handshake.transport_mut(),
                1,
            )
            .map_err(|_| "pairing_incomplete")?;
            pending
                .transaction
                .receive_ack(&peer_ack)
                .map_err(|_| "pairing_incomplete")?;
            if PRIVACY_PAUSED.load(Ordering::Acquire) {
                return Err("pairing_incomplete");
            }
            with_trust(|db| {
                pending.transaction.commit_local(db).map_err(|e| match e {
                    clipcore::pairing::PairingError::Trust(t) => t,
                    _ => clipcore::trust::TrustError::InvalidIdentity,
                })
            })
            .map_err(|_| "pairing_incomplete")?;
            pending.transaction.complete_here();
            Ok::<(), &'static str>(())
        })();
        if result.is_err() {
            let repair = with_trust(|db| {
                pending
                    .transaction
                    .observe_failure(db)
                    .map_err(|e| match e {
                        clipcore::pairing::PairingError::Trust(t) => t,
                        _ => clipcore::trust::TrustError::InvalidIdentity,
                    })
            });
            if repair.is_err()
                && matches!(
                    pending.transaction.state,
                    clipcore::pairing::State::NeedsRepair
                )
            {
                return Err("pairing_needs_repair");
            }
            return Err("pairing_incomplete");
        }
        Ok("trusted")
    };
    let text = match finish() {
        Ok(v) => v,
        Err(v) => v,
    };
    env.new_string(text)
        .map_or(std::ptr::null_mut(), |v| v.into_raw())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeRevokeDevice(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    device_id: JByteArray<'_>,
    public_key: JByteArray<'_>,
) -> jboolean {
    let Ok(device_id) = env.convert_byte_array(&device_id) else {
        return 0;
    };
    let Ok(public_key) = env.convert_byte_array(&public_key) else {
        return 0;
    };
    let (Some(device_id), Some(public_key)) = (decode_32(&device_id), decode_32(&public_key))
    else {
        return 0;
    };
    with_trust(|db| {
        db.revoke(
            device_id,
            public_key,
            clipcore::trust::RevocationReason::UserRequested,
        )
    })
    .map_or(0, |_| 1)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeSendText(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoint: JString<'_>,
    device_id: JByteArray<'_>,
    text: JString<'_>,
) -> jstring {
    if PRIVACY_PAUSED.load(Ordering::Acquire) {
        return env
            .new_string("privacy_paused")
            .map_or(std::ptr::null_mut(), |v| v.into_raw());
    }
    let result = (|| -> Result<(), &'static str> {
        let endpoint = utf8_string(&mut env, &endpoint).map_err(|_| "invalid_endpoint")?;
        let endpoint = endpoint
            .parse::<SocketAddr>()
            .map_err(|_| "invalid_endpoint")?;
        let id_bytes = env
            .convert_byte_array(&device_id)
            .map_err(|_| "invalid_device")?;
        let id = decode_32(&id_bytes).ok_or("invalid_device")?;
        let text = utf8_string(&mut env, &text).map_err(|_| "invalid_text")?;
        if text.is_empty() || text.len() > clipcore::MAX_TEXT_BYTES {
            return Err("payload_too_large");
        }
        let identity_record = ANDROID_IDENTITY
            .get()
            .and_then(|slot| {
                slot.lock()
                    .ok()?
                    .as_ref()
                    .map(|v| Zeroizing::new(v.to_record()))
            })
            .ok_or("identity_unavailable")?;
        let identity = DeviceIdentity::from_record(identity_record.as_ref())
            .map_err(|_| "identity_unavailable")?;
        let trust = trust_db_arc().ok_or("trust_store_unavailable")?;
        let mut session = clipcore::transport::TrustedLanSession::connect(
            endpoint,
            &identity,
            id,
            &trust,
            clipcore::CURRENT_PROTOCOL_VERSION,
        )
        .map_err(|_| "connection_failed")?;
        if PRIVACY_PAUSED.load(Ordering::Acquire) {
            return Err("privacy_paused");
        }
        session
            .send_text(0, text.into_bytes())
            .map_err(|_| "send_failed")?;
        Ok(())
    })();
    let code = result.map_or_else(|e| e, |_| "sent");
    env.new_string(code)
        .map_or(std::ptr::null_mut(), |v| v.into_raw())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeStartReceiver(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    bind_address: JString<'_>,
) -> jstring {
    if PRIVACY_PAUSED.load(Ordering::Acquire) {
        return std::ptr::null_mut();
    }
    let Ok(bind_address) = utf8_string(&mut env, &bind_address) else {
        return std::ptr::null_mut();
    };
    let Ok(address) = bind_address.parse::<SocketAddr>() else {
        return std::ptr::null_mut();
    };
    if !is_allowed_lan_bind(address.ip()) || address.port() != 0 {
        return std::ptr::null_mut();
    }
    let Ok(listener) = TcpListener::bind(address) else {
        return std::ptr::null_mut();
    };
    if listener.set_nonblocking(true).is_err() {
        return std::ptr::null_mut();
    }
    let Ok(local) = listener.local_addr() else {
        return std::ptr::null_mut();
    };
    let slot = LAN_LISTENER.get_or_init(|| Mutex::new(None));
    let Ok(mut current) = slot.lock() else {
        return std::ptr::null_mut();
    };
    *current = Some(listener);
    env.new_string(local.to_string())
        .map_or(std::ptr::null_mut(), |v| v.into_raw())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeStopReceiver(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) {
    if let Some(slot) = LAN_LISTENER.get()
        && let Ok(mut current) = slot.lock()
    {
        *current = None;
    }
}

/// Polls a nonblocking foreground listener. A returned frame is emitted only after Noise
/// authentication, local trust/revocation checks, sequence validation, and a post-receive
/// Privacy Pause check. The encoded result contains public peer metadata and the one-shot text.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_clipbridge_android_core_NativeCore_nativeReceiveText(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jbyteArray {
    if PRIVACY_PAUSED.load(Ordering::Acquire) {
        return std::ptr::null_mut();
    }
    let accepted = {
        let Some(slot) = LAN_LISTENER.get() else {
            return std::ptr::null_mut();
        };
        let Ok(current) = slot.lock() else {
            return std::ptr::null_mut();
        };
        let Some(listener) = current.as_ref() else {
            return std::ptr::null_mut();
        };
        match listener.accept() {
            Ok((stream, _)) => Some(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(_) => None,
        }
    };
    let Some(stream) = accepted else {
        return std::ptr::null_mut();
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .is_err()
        || stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .is_err()
    {
        return std::ptr::null_mut();
    }
    let Some(identity_record) = ANDROID_IDENTITY.get().and_then(|slot| {
        slot.lock()
            .ok()?
            .as_ref()
            .map(|v| Zeroizing::new(v.to_record()))
    }) else {
        return std::ptr::null_mut();
    };
    let Ok(identity) = DeviceIdentity::from_record(identity_record.as_ref()) else {
        return std::ptr::null_mut();
    };
    let Some(trust) = trust_db_arc() else {
        return std::ptr::null_mut();
    };
    let Ok(mut session) = clipcore::transport::TrustedLanSession::accept(
        stream,
        &identity,
        &trust,
        clipcore::CURRENT_PROTOCOL_VERSION,
    ) else {
        return std::ptr::null_mut();
    };
    if PRIVACY_PAUSED.load(Ordering::Acquire) {
        return std::ptr::null_mut();
    }
    let Ok(envelope) = session.receive_text(0) else {
        return std::ptr::null_mut();
    };
    if PRIVACY_PAUSED.load(Ordering::Acquire) || envelope.text.len() > clipcore::MAX_TEXT_BYTES {
        return std::ptr::null_mut();
    }
    let peer = session.peer_id().to_owned();
    let Ok(Some(device)) = trust
        .list_devices()
        .map(|rows| rows.into_iter().find(|d| d.device_id == peer))
    else {
        return std::ptr::null_mut();
    };
    let label = device.label.as_bytes();
    if label.len() > 64 {
        return std::ptr::null_mut();
    }
    let mut result = Vec::with_capacity(32 + 2 + label.len() + 4 + envelope.text.len());
    result.extend_from_slice(&peer);
    result.extend_from_slice(&(label.len() as u16).to_be_bytes());
    result.extend_from_slice(label);
    result.extend_from_slice(&(envelope.text.len() as u32).to_be_bytes());
    result.extend_from_slice(&envelope.text);
    env.byte_array_from_slice(&result)
        .map_or(std::ptr::null_mut(), |v| v.into_raw())
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

    #[test]
    fn listener_bind_policy_allows_local_and_rejects_unspecified_or_public_addresses() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        assert!(is_allowed_lan_bind(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 4
        ))));
        assert!(is_allowed_lan_bind(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_allowed_lan_bind(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_allowed_lan_bind(IpAddr::V6("fd00::1".parse().unwrap())));
        assert!(!is_allowed_lan_bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!is_allowed_lan_bind(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_allowed_lan_bind(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }
}

