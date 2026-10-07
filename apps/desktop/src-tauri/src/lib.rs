use std::{
    fs,
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use clipcore::{
    CURRENT_PROTOCOL_VERSION,
    identity::{DeviceIdentity, IdentityError, IdentityManager},
    trust::{RevocationReason, TrustDb, TrustStatus},
};
use serde::{Deserialize, Serialize};
use tauri::{
    Emitter, Manager, State,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceView {
    id: String,
    label: String,
    platform: String,
    trust_state: String,
    connectivity: String,
    fingerprint: String,
    trusted_at: i64,
    minimum_protocol: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalDevice {
    label: String,
    platform: String,
    device_id: String,
    fingerprint: String,
    protocol_version: u16,
    identity_status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppStatus {
    identity_status: &'static str,
    trust_db_status: &'static str,
    secure_store_status: &'static str,
    lan_status: &'static str,
    session_status: &'static str,
    platform: String,
    protocol_version: u16,
    app_version: &'static str,
    last_error: Option<String>,
    privacy_paused: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct IncomingText {
    device_id: String,
    label: String,
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingInvitationView {
    payload_hex: String,
    expires_in_seconds: u64,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct PairingReadyView {
    sas: String,
    peer_fingerprint: String,
    role: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingOutcome {
    state: String,
    device_id: String,
    label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    appearance: String,
    privacy_paused: bool,
    activity_retention_days: u16,
    start_minimized: bool,
    notifications: bool,
    tray_behavior: String,
    lan_enabled: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            appearance: "system".into(),
            privacy_paused: false,
            activity_retention_days: 7,
            start_minimized: false,
            notifications: true,
            tray_behavior: "minimize".into(),
            lan_enabled: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ActivityEvent {
    kind: String,
    device: Option<String>,
    timestamp: i64,
    route: Option<String>,
    result: String,
}

struct AppState {
    identity: Option<Arc<DeviceIdentity>>,
    trust: Option<Arc<TrustDb>>,
    settings_path: PathBuf,
    activity_path: PathBuf,
    settings: Arc<Mutex<Settings>>,
    last_error: Mutex<Option<String>>,
    secure_store_status: &'static str,
    trust_db_status: &'static str,
    lan_status: &'static str,
    lan_port: Option<u16>,
    tray_available: bool,
    pairing: Arc<Mutex<PairingRuntime>>,
}

struct PendingPairing {
    stream: TcpStream,
    handshake: clipcore::session::PairingHandshake,
    transaction: clipcore::pairing::PairingTransaction,
}

#[derive(Default)]
struct PairingRuntime {
    issuer: clipcore::pairing::InvitationIssuer,
    pending: Option<PendingPairing>,
    invitation_cancel: Option<Arc<AtomicBool>>,
    clock: Option<Instant>,
    issued_at: Option<Duration>,
}

#[allow(dead_code)]
struct TrayHolder(tauri::tray::TrayIcon);

fn safe_error(error: &IdentityError) -> &'static str {
    match error {
        IdentityError::StoreUnavailable | IdentityError::StoreLocked => "secure_store_unavailable",
        IdentityError::StorePermissionDenied => "secure_store_permission_denied",
        IdentityError::Malformed | IdentityError::KeyMismatch => "identity_corrupt",
        IdentityError::Missing => "identity_missing",
        IdentityError::AlreadyExists => "identity_exists",
        IdentityError::StoreDeletionFailed => "secure_store_delete_failed",
        _ => "identity_store_error",
    }
}

#[cfg(windows)]
fn load_or_create_identity() -> Result<DeviceIdentity, IdentityError> {
    use clipcore::store::windows::WindowsCredentialStore;
    let manager = IdentityManager::new(std::sync::Arc::new(WindowsCredentialStore::default()));
    match manager.load_existing() {
        Ok(identity) => Ok(identity),
        Err(IdentityError::Missing) => manager.create_new(),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn load_or_create_identity() -> Result<DeviceIdentity, IdentityError> {
    use clipcore::store::linux::LinuxSecretServiceStore;
    let manager = IdentityManager::new(std::sync::Arc::new(LinuxSecretServiceStore));
    match manager.load_existing() {
        Ok(identity) => Ok(identity),
        Err(IdentityError::Missing) => manager.create_new(),
        Err(error) => Err(error),
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn load_or_create_identity() -> Result<DeviceIdentity, IdentityError> {
    Err(IdentityError::StoreUnavailable)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let temp = path.with_extension("tmp");
    let bytes = serde_json::to_vec(value).map_err(|_| "settings_encode_failed")?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options
        .open(&temp)
        .and_then(|mut file| file.write_all(&bytes))
        .map_err(|_| "app_data_write_failed")?;
    fs::rename(&temp, path).map_err(|_| "app_data_commit_failed".to_owned())
}

fn validate_settings(settings: &Settings) -> Result<(), String> {
    if !["system", "light", "dark"].contains(&settings.appearance.as_str())
        || settings.activity_retention_days > 365
        || !["minimize", "quit"].contains(&settings.tray_behavior.as_str())
    {
        return Err("invalid_settings".into());
    }
    Ok(())
}

fn load_settings(path: &Path) -> Settings {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn read_activity(path: &Path) -> Vec<ActivityEvent> {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn record_activity(path: &Path, event: ActivityEvent) {
    let mut events = read_activity(path);
    events.push(event);
    events.truncate(500);
    let _ = write_json_atomic(path, &events);
}

fn activity_with_retention(path: &Path, retention_days: u16) -> Vec<ActivityEvent> {
    let cutoff = unix_now().saturating_sub(i64::from(retention_days) * 86_400);
    let mut events = read_activity(path);
    events.retain(|event| event.timestamp >= cutoff);
    let _ = write_json_atomic(path, &events);
    events
}

fn start_lan_listener(
    app: tauri::AppHandle,
    identity: Arc<DeviceIdentity>,
    trust: Arc<TrustDb>,
    settings: Arc<Mutex<Settings>>,
    activity_path: PathBuf,
) -> Result<u16, String> {
    let listener = TcpListener::bind(("0.0.0.0", 0)).map_err(|_| "lan_listener_unavailable")?;
    let port = listener
        .local_addr()
        .map_err(|_| "lan_listener_unavailable")?
        .port();
    let active_workers = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for accepted in listener.incoming() {
            let Ok(socket) = accepted else { continue };
            // Bound concurrent unauthenticated handshakes so LAN peers cannot create unbounded
            // worker threads. Authentication happens before any application envelope is read.
            if active_workers.fetch_add(1, Ordering::AcqRel) >= 8 {
                active_workers.fetch_sub(1, Ordering::AcqRel);
                continue;
            }
            let identity = Arc::clone(&identity);
            let trust = Arc::clone(&trust);
            let settings = Arc::clone(&settings);
            let app = app.clone();
            let activity_path = activity_path.clone();
            let active_workers = Arc::clone(&active_workers);
            thread::spawn(move || {
                let result = (|| {
                    if settings.lock().map_err(|_| "state_error")?.privacy_paused
                        || !settings.lock().map_err(|_| "state_error")?.lan_enabled
                    {
                        return Err("privacy_paused");
                    }
                    let mut session = clipcore::transport::TrustedLanSession::accept(
                        socket,
                        &identity,
                        &trust,
                        CURRENT_PROTOCOL_VERSION,
                    )
                    .map_err(|_| "auth_failed")?;
                    let peer_id = *session.peer_id();
                    let envelope = session.receive_text(0).map_err(|_| "invalid_envelope")?;
                    if settings.lock().map_err(|_| "state_error")?.privacy_paused {
                        return Err("privacy_paused");
                    }
                    let peer = trust
                        .list_devices()
                        .map_err(|_| "trust_db_unavailable")?
                        .into_iter()
                        .find(|peer| peer.device_id == peer_id)
                        .ok_or("peer_untrusted")?;
                    let text = String::from_utf8(envelope.text).map_err(|_| "invalid_envelope")?;
                    record_activity(
                        &activity_path,
                        ActivityEvent {
                            kind: "text_received".into(),
                            device: Some(short(&peer_id)),
                            timestamp: unix_now(),
                            route: Some("LAN Direct".into()),
                            result: "received".into(),
                        },
                    );
                    app.emit(
                        "incoming-text",
                        IncomingText {
                            device_id: hex(&peer_id),
                            label: peer.label,
                            text,
                        },
                    )
                    .map_err(|_| "delivery_failed")?;
                    Ok::<(), &'static str>(())
                })();
                if let Err(code) = result
                    && code != "privacy_paused"
                    && code != "auth_failed"
                {
                    let _ = app.emit("lan-error", code);
                    if code != "invalid_envelope" {
                        record_activity(
                            &activity_path,
                            ActivityEvent {
                                kind: "connection_failed".into(),
                                device: None,
                                timestamp: unix_now(),
                                route: Some("LAN Direct".into()),
                                result: code.into(),
                            },
                        );
                    }
                }
                active_workers.fetch_sub(1, Ordering::AcqRel);
            });
        }
    });
    Ok(port)
}

fn local_lan_address(port: u16) -> Option<SocketAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // UDP connect selects a local route without sending a packet.
    socket.connect("192.0.2.1:9").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        return None;
    }
    Some(SocketAddr::new(ip, port))
}

#[tauri::command]
fn get_local_device(state: State<'_, AppState>) -> LocalDevice {
    let fingerprint = state
        .identity
        .as_ref()
        .map(|identity| identity.fingerprint())
        .unwrap_or_default();
    LocalDevice {
        label: whoami_label(),
        platform: platform(),
        device_id: fingerprint.clone(),
        fingerprint,
        protocol_version: CURRENT_PROTOCOL_VERSION,
        identity_status: if state.identity.is_some() {
            "ready"
        } else {
            "unavailable"
        },
    }
}

#[tauri::command]
fn list_devices(state: State<'_, AppState>) -> Result<Vec<DeviceView>, String> {
    let Some(trust) = state.trust.as_ref() else {
        return Ok(Vec::new());
    };
    let mut result = trust
        .list_devices()
        .map_err(|_| "trust_db_unavailable".to_owned())?
        .into_iter()
        .map(|device| {
            let id = hex(&device.device_id);
            DeviceView {
                id,
                label: device.label,
                platform: "Desktop".into(),
                trust_state: if device.status == TrustStatus::Trusted {
                    "trusted"
                } else {
                    "needs_repair"
                }
                .into(),
                connectivity: "offline".into(),
                fingerprint: hex(&device.device_id),
                trusted_at: device.trusted_at,
                minimum_protocol: device.minimum_protocol,
            }
        })
        .collect::<Vec<_>>();
    let revoked = trust
        .list_revoked()
        .map_err(|_| "trust_db_unavailable".to_owned())?;
    result.extend(revoked.into_iter().map(|device| {
        let id = hex(&device.device_id);
        DeviceView {
            id,
            label: "Revoked device".into(),
            platform: "Desktop".into(),
            trust_state: "revoked".into(),
            connectivity: "revoked".into(),
            fingerprint: hex(&device.device_id),
            trusted_at: device.revoked_at,
            minimum_protocol: CURRENT_PROTOCOL_VERSION,
        }
    }));
    Ok(result)
}

#[tauri::command]
fn revoke_device(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let device_id = parse_hex32(&id).ok_or("invalid_device_id")?;
    let trust = state.trust.as_ref().ok_or("trust_db_unavailable")?;
    let device = trust
        .list_devices()
        .map_err(|_| "trust_db_unavailable")?
        .into_iter()
        .find(|d| d.device_id == device_id)
        .ok_or("peer_untrusted")?;
    trust
        .revoke(
            device_id,
            device.public_key,
            RevocationReason::UserRequested,
        )
        .map_err(|_| "revoke_failed")?;
    record_activity(
        &state.activity_path,
        ActivityEvent {
            kind: "device_revoked".into(),
            device: Some(short(&device_id)),
            timestamp: unix_now(),
            route: None,
            result: "revoked".into(),
        },
    );
    Ok(())
}

#[tauri::command]
fn get_lan_endpoint(state: State<'_, AppState>) -> Result<String, String> {
    let port = state.lan_port.ok_or("lan_unavailable")?;
    local_lan_address(port)
        .map(|address| address.to_string())
        .ok_or_else(|| "lan_address_unavailable".into())
}

#[tauri::command]
fn create_pairing_invitation(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<PairingInvitationView, String> {
    if state
        .settings
        .lock()
        .map_err(|_| "state_error")?
        .privacy_paused
    {
        return Err("privacy_paused".into());
    }
    let identity = Arc::clone(state.identity.as_ref().ok_or("secure_store_unavailable")?);
    let port_listener = TcpListener::bind(("0.0.0.0", 0)).map_err(|_| "lan_unavailable")?;
    port_listener
        .set_nonblocking(true)
        .map_err(|_| "lan_unavailable")?;
    let port = port_listener
        .local_addr()
        .map_err(|_| "lan_unavailable")?
        .port();
    let endpoint = local_lan_address(port)
        .ok_or("lan_address_unavailable")?
        .to_string();
    let (qr, payload) = {
        let mut pairing = state.pairing.lock().map_err(|_| "pairing_state_error")?;
        if let Some(cancel) = pairing.invitation_cancel.take() {
            cancel.store(true, Ordering::Release);
        }
        let clock = *pairing.clock.get_or_insert_with(Instant::now);
        let now = clock.elapsed();
        let (qr, payload) = pairing
            .issuer
            .issue(now, &identity, vec![endpoint])
            .map_err(|_| "pairing_invitation_failed")?;
        pairing.pending = None;
        pairing.issued_at = Some(now);
        (qr, payload)
    };
    let cancel = Arc::new(AtomicBool::new(false));
    state
        .pairing
        .lock()
        .map_err(|_| "pairing_state_error")?
        .invitation_cancel = Some(Arc::clone(&cancel));
    let pairing = Arc::clone(&state.pairing);
    let identity_clone = Arc::clone(&identity);
    thread::spawn(move || {
        let expiry = Instant::now() + Duration::from_secs(120);
        while !cancel.load(Ordering::Acquire) && Instant::now() < expiry {
            match port_listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
                    let result = clipcore::session::establish_pairing(
                        &mut stream,
                        &identity_clone,
                        &qr,
                        false,
                        CURRENT_PROTOCOL_VERSION,
                    );
                    let Ok(handshake) = result else { continue };
                    let now = pairing
                        .lock()
                        .ok()
                        .and_then(|p| p.clock.map(|c| c.elapsed()))
                        .unwrap_or_default();
                    let Ok(mut p) = pairing.lock() else { break };
                    if p.issuer.start(now, qr.nonce).is_err() {
                        break;
                    }
                    let transaction =
                        clipcore::pairing::PairingTransaction::from_verified_handshake(
                            &identity_clone,
                            &handshake,
                            "New device".into(),
                        );
                    let event = PairingReadyView {
                        sas: transaction.sas().to_owned(),
                        peer_fingerprint: hex(blake3::hash(handshake.remote_static()).as_bytes()),
                        role: "issuer".into(),
                    };
                    p.pending = Some(PendingPairing {
                        stream,
                        handshake,
                        transaction,
                    });
                    p.issued_at = None;
                    let _ = app.emit("pairing-ready", event);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50))
                }
                Err(_) => break,
            }
        }
    });
    let payload_hex = hex(&payload);
    Ok(PairingInvitationView {
        payload_hex,
        expires_in_seconds: 120,
    })
}

#[tauri::command]
fn cancel_pairing_invitation(state: State<'_, AppState>) -> Result<(), String> {
    let mut pairing = state.pairing.lock().map_err(|_| "pairing_state_error")?;
    if let Some(cancel) = pairing.invitation_cancel.take() {
        cancel.store(true, Ordering::Release);
    }
    pairing.issuer.cancel();
    pairing.issued_at = None;
    pairing.pending = None;
    Ok(())
}

#[tauri::command]
fn get_pairing_invitation_remaining(state: State<'_, AppState>) -> Option<u64> {
    let mut pairing = state.pairing.lock().ok()?;
    let issued_at = pairing.issued_at?;
    let now = pairing.clock?.elapsed();
    let elapsed = now.saturating_sub(issued_at).as_secs();
    if elapsed >= 120 {
        pairing.issuer.cancel();
        if let Some(cancel) = pairing.invitation_cancel.take() {
            cancel.store(true, Ordering::Release);
        }
        pairing.issued_at = None;
        return None;
    }
    Some(120 - elapsed)
}

#[tauri::command]
fn join_pairing(
    payload_hex: String,
    label: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<PairingReadyView, String> {
    if state
        .settings
        .lock()
        .map_err(|_| "state_error")?
        .privacy_paused
    {
        return Err("privacy_paused".into());
    }
    if payload_hex.len() > 1024
        || !payload_hex.len().is_multiple_of(2)
        || !payload_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid_pairing_input".into());
    }
    if label.trim().is_empty() || label.len() > 64 || label.chars().any(char::is_control) {
        return Err("invalid_device_label".into());
    }
    let payload = decode_hex(&payload_hex).ok_or("invalid_pairing_input")?;
    let qr = clipcore::qr::PairingQr::decode(&payload).map_err(|_| "invalid_pairing_input")?;
    let endpoint = qr
        .endpoints
        .first()
        .ok_or("pairing_endpoint_missing")?
        .parse::<SocketAddr>()
        .map_err(|_| "invalid_pairing_endpoint")?;
    let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(8))
        .map_err(|_| "lan_unreachable")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| "lan_unreachable")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| "lan_unreachable")?;
    let identity = state
        .identity
        .as_deref()
        .ok_or("secure_store_unavailable")?;
    let handshake = clipcore::session::establish_pairing(
        &mut stream,
        identity,
        &qr,
        true,
        CURRENT_PROTOCOL_VERSION,
    )
    .map_err(|_| "auth_failed")?;
    let transaction = clipcore::pairing::PairingTransaction::from_verified_handshake(
        identity,
        &handshake,
        label.trim().to_owned(),
    );
    let event = PairingReadyView {
        sas: transaction.sas().to_owned(),
        peer_fingerprint: hex(blake3::hash(handshake.remote_static()).as_bytes()),
        role: "joiner".into(),
    };
    state
        .pairing
        .lock()
        .map_err(|_| "pairing_state_error")?
        .pending = Some(PendingPairing {
        stream,
        handshake,
        transaction,
    });
    app.emit("pairing-ready", event.clone())
        .map_err(|_| "pairing_event_failed")?;
    Ok(event)
}

#[tauri::command]
fn confirm_pairing(accepted: bool, state: State<'_, AppState>) -> Result<PairingOutcome, String> {
    if state
        .settings
        .lock()
        .map_err(|_| "state_error")?
        .privacy_paused
    {
        return Err("privacy_paused".into());
    }
    let mut pending = state
        .pairing
        .lock()
        .map_err(|_| "pairing_state_error")?
        .pending
        .take()
        .ok_or("pairing_not_ready")?;
    let trust = state.trust.as_deref().ok_or("trust_db_unavailable")?;
    if !accepted {
        let _ = pending.transaction.confirm_local(false);
        record_activity(
            &state.activity_path,
            ActivityEvent {
                kind: "pairing_failed".into(),
                device: None,
                timestamp: unix_now(),
                route: None,
                result: "sas_mismatch".into(),
            },
        );
        return Err("pairing_rejected".into());
    }
    let protocol_result = (|| {
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
        let remote_confirm = clipcore::session::receive_pair_control(
            &mut pending.stream,
            pending.handshake.transport_mut(),
            0,
        )
        .map_err(|_| "pairing_incomplete")?;
        pending
            .transaction
            .receive_confirm(&remote_confirm)
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
        let remote_ack = clipcore::session::receive_pair_control(
            &mut pending.stream,
            pending.handshake.transport_mut(),
            1,
        )
        .map_err(|_| "pairing_incomplete")?;
        pending
            .transaction
            .receive_ack(&remote_ack)
            .map_err(|_| "pairing_incomplete")?;
        pending
            .transaction
            .commit_local(trust)
            .map_err(|_| "pairing_incomplete")?;
        Ok::<(), &'static str>(())
    })();
    if protocol_result.is_err() {
        let recovery = pending.transaction.observe_failure(trust);
        if matches!(recovery, Err(clipcore::pairing::PairingError::NeedsRepair)) {
            record_activity(
                &state.activity_path,
                ActivityEvent {
                    kind: "pairing_failed".into(),
                    device: Some(short(pending.transaction.peer_id())),
                    timestamp: unix_now(),
                    route: Some("LAN Direct".into()),
                    result: "pairing_incomplete".into(),
                },
            );
            return Err("pairing_needs_repair".into());
        }
        return Err("pairing_incomplete".into());
    }
    pending.transaction.complete_here();
    let device_id = hex(pending.transaction.peer_id());
    let label = pending.transaction.label().to_owned();
    record_activity(
        &state.activity_path,
        ActivityEvent {
            kind: "pairing_completed".into(),
            device: Some(short(pending.transaction.peer_id())),
            timestamp: unix_now(),
            route: Some("LAN Direct".into()),
            result: "trusted".into(),
        },
    );
    Ok(PairingOutcome {
        state: "trusted".into(),
        device_id,
        label,
    })
}

#[tauri::command]
fn send_text(
    device_id: String,
    address: String,
    text: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let peer_id = parse_hex32(&device_id).ok_or("invalid_device_id")?;
    let destination = address
        .parse::<SocketAddr>()
        .map_err(|_| "invalid_lan_address")?;
    if text.is_empty() || text.len() > clipcore::MAX_TEXT_BYTES {
        return Err("payload_too_large".into());
    }
    let settings = state.settings.lock().map_err(|_| "state_error")?;
    if settings.privacy_paused {
        return Err("privacy_paused".into());
    }
    if !settings.lan_enabled {
        return Err("lan_disabled".into());
    }
    drop(settings);
    let identity = state
        .identity
        .as_deref()
        .ok_or("secure_store_unavailable")?;
    let trust = state.trust.as_deref().ok_or("trust_db_unavailable")?;
    let mut session = clipcore::transport::TrustedLanSession::connect(
        destination,
        identity,
        peer_id,
        trust,
        CURRENT_PROTOCOL_VERSION,
    )
    .map_err(|error| {
        if error.to_string().contains("identity_mismatch") {
            "identity_mismatch"
        } else if error.to_string().contains("untrusted") {
            "peer_untrusted"
        } else {
            "lan_unreachable"
        }
    })?;
    session
        .send_text(0, text.into_bytes())
        .map_err(|_| "send_failed")?;
    record_activity(
        &state.activity_path,
        ActivityEvent {
            kind: "text_sent".into(),
            device: Some(short(&peer_id)),
            timestamp: unix_now(),
            route: Some("LAN Direct".into()),
            result: "sent".into(),
        },
    );
    Ok(())
}

#[tauri::command]
fn get_settings(state: State<'_, AppState>) -> Settings {
    state.settings.lock().expect("settings lock").clone()
}

#[tauri::command]
fn update_settings(settings: Settings, state: State<'_, AppState>) -> Result<Settings, String> {
    validate_settings(&settings)?;
    write_json_atomic(&state.settings_path, &settings)?;
    *state.settings.lock().expect("settings lock") = settings.clone();
    if settings.privacy_paused {
        let mut pairing = state.pairing.lock().map_err(|_| "pairing_state_error")?;
        if let Some(cancel) = pairing.invitation_cancel.take() {
            cancel.store(true, Ordering::Release);
        }
        pairing.issuer.cancel();
        pairing.issued_at = None;
        pairing.pending = None;
    }
    let _ = activity_with_retention(&state.activity_path, settings.activity_retention_days);
    Ok(settings)
}

#[tauri::command]
fn set_privacy_pause(paused: bool, state: State<'_, AppState>) -> Result<(), String> {
    let mut settings = state.settings.lock().expect("settings lock");
    let mut next = settings.clone();
    next.privacy_paused = paused;
    write_json_atomic(&state.settings_path, &next)?;
    *settings = next;
    drop(settings);
    if paused {
        let mut pairing = state.pairing.lock().map_err(|_| "pairing_state_error")?;
        if let Some(cancel) = pairing.invitation_cancel.take() {
            cancel.store(true, Ordering::Release);
        }
        pairing.issuer.cancel();
        pairing.issued_at = None;
        pairing.pending = None;
    }
    Ok(())
}

#[tauri::command]
fn get_activity(state: State<'_, AppState>) -> Vec<ActivityEvent> {
    let retention = state
        .settings
        .lock()
        .expect("settings lock")
        .activity_retention_days;
    activity_with_retention(&state.activity_path, retention)
}

#[tauri::command]
fn get_diagnostics(state: State<'_, AppState>) -> AppStatus {
    let settings = state.settings.lock().expect("settings lock");
    AppStatus {
        identity_status: if state.identity.is_some() {
            "ready"
        } else {
            "unavailable"
        },
        trust_db_status: state.trust_db_status,
        secure_store_status: state.secure_store_status,
        lan_status: state.lan_status,
        session_status: "disconnected",
        platform: platform(),
        protocol_version: CURRENT_PROTOCOL_VERSION,
        app_version: env!("CARGO_PKG_VERSION"),
        last_error: state.last_error.lock().expect("error lock").clone(),
        privacy_paused: settings.privacy_paused,
    }
}

fn platform() -> String {
    if cfg!(target_os = "windows") {
        "Windows".into()
    } else if cfg!(target_os = "linux") {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            "Linux · Wayland".into()
        } else if std::env::var_os("DISPLAY").is_some() {
            "Linux · X11".into()
        } else {
            "Linux · display unavailable".into()
        }
    } else {
        "Unsupported platform".into()
    }
}
fn whoami_label() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "This device".into())
        .chars()
        .take(64)
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn short(bytes: &[u8]) -> String {
    hex(bytes).chars().take(12).collect()
}
fn parse_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut out = [0; 32];
    for (i, item) in out.iter_mut().enumerate() {
        *item = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect()
}
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let data = app.path().app_data_dir()?;
            fs::create_dir_all(&data)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
            }
            let (identity, secure_store_status, identity_error) = match load_or_create_identity() {
                Ok(identity) => (Some(Arc::new(identity)), "available", None),
                Err(error) => {
                    let code = safe_error(&error);
                    eprintln!("identity startup failed: {code}");
                    (
                        None,
                        if code == "secure_store_unavailable" {
                            "unavailable"
                        } else {
                            "error"
                        },
                        Some(code.to_owned()),
                    )
                }
            };
            let (trust, trust_db_status, trust_error) =
                match TrustDb::open(data.join("trust.sqlite")) {
                    Ok(trust) => (Some(Arc::new(trust)), "ready", None),
                    Err(_) => (None, "unavailable", Some("trust_db_unavailable".to_owned())),
                };
            let settings_path = data.join("settings.json");
            let activity_path = data.join("activity.json");
            let settings = load_settings(&settings_path);
            let settings = Arc::new(Mutex::new(settings));
            let lan_port = match (identity.as_ref(), trust.as_ref()) {
                (Some(identity), Some(trust)) => start_lan_listener(
                    app.handle().clone(),
                    Arc::clone(identity),
                    Arc::clone(trust),
                    Arc::clone(&settings),
                    activity_path.clone(),
                )
                .ok(),
                _ => None,
            };
            let lan_status = if lan_port.is_some() {
                "available"
            } else {
                "unavailable"
            };
            let status_label = if settings.lock().map(|s| s.privacy_paused).unwrap_or(false) {
                "Connection status: paused"
            } else if lan_port.is_some() {
                "Connection status: LAN ready"
            } else {
                "Connection status: unavailable"
            };
            let open = MenuItem::with_id(app, "open", "Open app", true, None::<&str>)?;
            let send_clipboard =
                MenuItem::with_id(app, "send-clipboard", "Send Clipboard…", true, None::<&str>)?;
            let compose = MenuItem::with_id(app, "compose", "Compose", true, None::<&str>)?;
            let pause = MenuItem::with_id(app, "pause", "Privacy Pause", true, None::<&str>)?;
            let status = MenuItem::with_id(app, "status", status_label, false, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let separator = PredefinedMenuItem::separator(app)?;
            let menu = Menu::with_items(
                app,
                &[
                    &open,
                    &send_clipboard,
                    &compose,
                    &pause,
                    &separator,
                    &status,
                    &quit,
                ],
            )?;
            let tray = image::load_from_memory(include_bytes!("../icons/icon.png"))
                .ok()
                .map(|icon| {
                    let rgba = icon.to_rgba8();
                    tauri::image::Image::new_owned(rgba.into_raw(), icon.width(), icon.height())
                })
                .and_then(|icon| {
                    TrayIconBuilder::new()
                        .icon(icon)
                        .menu(&menu)
                        .tooltip("ClipBridge")
                        .build(app)
                        .ok()
                });
            let tray_available = tray.is_some();
            if let Some(tray) = tray {
                app.manage(TrayHolder(tray));
            }
            app.manage(AppState {
                identity,
                trust,
                settings_path,
                activity_path,
                settings,
                last_error: Mutex::new(identity_error.or(trust_error)),
                secure_store_status,
                trust_db_status,
                lan_status,
                lan_port,
                tray_available,
                pairing: Arc::new(Mutex::new(PairingRuntime::default())),
            });
            let state = app.state::<AppState>();
            let start_minimized = state
                .settings
                .lock()
                .map(|s| s.start_minimized)
                .unwrap_or(false);
            if start_minimized
                && state.tray_available
                && let Some(window) = app.get_webview_window("main")
            {
                let _ = window.hide();
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                let app_state = app.state::<AppState>();
                let minimize = app_state.tray_available
                    && app_state
                        .settings
                        .lock()
                        .map(|s| s.tray_behavior == "minimize")
                        .unwrap_or(false);
                if minimize {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "send-clipboard" => {
                let _ = app.emit("tray-action", "clipboard");
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "compose" => {
                let _ = app.emit("tray-action", "compose");
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "pause" => {
                let state = app.state::<AppState>();
                let paused = state
                    .settings
                    .lock()
                    .map(|s| s.privacy_paused)
                    .unwrap_or(false);
                let _ = set_privacy_pause(!paused, state);
                let _ = app.emit("tray-state-changed", !paused);
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            get_local_device,
            list_devices,
            revoke_device,
            get_lan_endpoint,
            create_pairing_invitation,
            cancel_pairing_invitation,
            get_pairing_invitation_remaining,
            join_pairing,
            confirm_pairing,
            send_text,
            get_settings,
            update_settings,
            set_privacy_pause,
            get_activity,
            get_diagnostics
        ])
        .run(tauri::generate_context!())
        .expect("ClipBridge desktop runtime failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_or_non_hex_device_ids() {
        assert!(parse_hex32("aa").is_none());
        assert!(parse_hex32(&"gg".repeat(32)).is_none());
        assert_eq!(parse_hex32(&"ab".repeat(32)), Some([0xab; 32]));
    }

    #[test]
    fn validates_settings_at_the_rust_boundary() {
        let mut settings = Settings::default();
        assert!(validate_settings(&settings).is_ok());
        settings.appearance = "neon".into();
        assert_eq!(validate_settings(&settings), Err("invalid_settings".into()));
    }

    #[test]
    fn diagnostics_schema_has_no_secret_or_content_fields() {
        let serialized = serde_json::to_value(AppStatus {
            identity_status: "ready",
            trust_db_status: "ready",
            secure_store_status: "available",
            lan_status: "not_started",
            session_status: "disconnected",
            platform: "Windows".into(),
            protocol_version: 1,
            app_version: "0.1.0",
            last_error: None,
            privacy_paused: false,
        })
        .unwrap();
        let fields = serialized.as_object().unwrap();
        assert_eq!(fields.len(), 10);
        assert!(!fields.contains_key("privateKey"));
        assert!(!fields.contains_key("payload"));
        assert!(!fields.contains_key("path"));
    }

    #[test]
    fn activity_retention_persists_only_metadata_and_prunes_expired_rows() {
        let directory =
            std::env::temp_dir().join(format!("clipbridge-activity-{}", uuid_for_test()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("activity.json");
        write_json_atomic(
            &path,
            &vec![ActivityEvent {
                kind: "text_sent".into(),
                device: Some("a1b2c3".into()),
                timestamp: 1,
                route: Some("LAN".into()),
                result: "sent".into(),
            }],
        )
        .unwrap();
        assert!(activity_with_retention(&path, 1).is_empty());
        let bytes = fs::read_to_string(&path).unwrap();
        assert_eq!(bytes, "[]");
        assert!(!bytes.contains("payload"));
        let _ = fs::remove_dir_all(directory);
    }

    fn uuid_for_test() -> String {
        format!("{}-{}", std::process::id(), unix_now())
    }
}
