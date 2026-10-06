//! Local-only identity trust and revocation database. No application payloads are stored here.
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("trust database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("invalid trusted identity")]
    InvalidIdentity,
    #[error("device is revoked")]
    Revoked,
    #[error("device is not trusted")]
    Untrusted,
    #[error("device requires explicit pairing repair")]
    NeedsRepair,
    #[error("device key conflicts with existing trust")]
    KeyConflict,
    #[error("device id conflicts with its public key")]
    DeviceIdMismatch,
    #[error("trusted session was revoked")]
    SessionRevoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStatus {
    Trusted,
    NeedsRepair,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDevice {
    pub record_id: Uuid,
    pub device_id: [u8; 32],
    pub public_key: [u8; 32],
    pub label: String,
    pub minimum_protocol: u16,
    pub trusted_at: i64,
    pub status: TrustStatus,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedDevice {
    pub device_id: [u8; 32],
    pub public_key: [u8; 32],
    pub revoked_at: i64,
    pub reason_code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    UserRequested,
    DeviceLost,
    SuspectedCompromise,
    IdentityReplaced,
    StalePairing,
}
impl RevocationReason {
    fn code(self) -> &'static str {
        match self {
            Self::UserRequested => "user_requested",
            Self::DeviceLost => "device_lost",
            Self::SuspectedCompromise => "suspected_compromise",
            Self::IdentityReplaced => "identity_replaced",
            Self::StalePairing => "stale_pairing",
        }
    }
}

#[derive(Default)]
struct SessionRegistry {
    sessions: Mutex<HashMap<[u8; 32], Vec<Weak<AtomicBool>>>>,
}
pub struct ActiveSession {
    live: Arc<AtomicBool>,
}
impl ActiveSession {
    pub fn is_active(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
    pub fn ensure_active(&self) -> Result<(), TrustError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(TrustError::SessionRevoked)
        }
    }
}
impl SessionRegistry {
    fn register(&self, device_id: [u8; 32]) -> ActiveSession {
        let live = Arc::new(AtomicBool::new(true));
        self.sessions
            .lock()
            .expect("session registry poisoned")
            .entry(device_id)
            .or_default()
            .push(Arc::downgrade(&live));
        ActiveSession { live }
    }
    pub fn terminate(&self, device_id: &[u8; 32]) {
        if let Some(sessions) = self
            .sessions
            .lock()
            .expect("session registry poisoned")
            .remove(device_id)
        {
            for session in sessions {
                if let Some(session) = session.upgrade() {
                    session.store(false, Ordering::Release);
                }
            }
        }
    }
}

pub struct TrustDb {
    connection: Mutex<Connection>,
    sessions: Arc<SessionRegistry>,
}
impl TrustDb {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, TrustError> {
        Self::from_connection(Connection::open(path)?)
    }
    pub fn in_memory() -> Result<Self, TrustError> {
        Self::from_connection(Connection::open_in_memory()?)
    }
    fn from_connection(connection: Connection) -> Result<Self, TrustError> {
        connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;
          CREATE TABLE IF NOT EXISTS trusted_devices(
            record_id TEXT NOT NULL PRIMARY KEY, device_id BLOB NOT NULL UNIQUE CHECK(length(device_id)=32),
            static_public_key BLOB NOT NULL UNIQUE CHECK(length(static_public_key)=32), local_label TEXT NOT NULL CHECK(length(local_label)<=64),
            minimum_protocol INTEGER NOT NULL CHECK(minimum_protocol BETWEEN 1 AND 65535), trusted_at INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('trusted','needs_repair')));
          CREATE TABLE IF NOT EXISTS revoked_devices(
            device_id BLOB NOT NULL PRIMARY KEY CHECK(length(device_id)=32), static_public_key BLOB NOT NULL CHECK(length(static_public_key)=32),
            revoked_at INTEGER NOT NULL, reason_code TEXT NOT NULL CHECK(length(reason_code) BETWEEN 1 AND 64));")?;
        Ok(Self {
            connection: Mutex::new(connection),
            sessions: Arc::new(SessionRegistry::default()),
        })
    }
    pub(crate) fn commit_trust(
        &self,
        device_id: [u8; 32],
        public_key: [u8; 32],
        label: &str,
        min_protocol: u16,
    ) -> Result<TrustedDevice, TrustError> {
        if *blake3::hash(&public_key).as_bytes() != device_id
            || label.len() > 64
            || min_protocol == 0
        {
            return Err(TrustError::InvalidIdentity);
        }
        let mut conn = self.connection.lock().expect("trust db poisoned");
        let tx = conn.transaction()?;
        if tx
            .query_row(
                "SELECT 1 FROM revoked_devices WHERE device_id=?1",
                [&device_id[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(TrustError::Revoked);
        }
        let by_id: Option<Vec<u8>> = tx
            .query_row(
                "SELECT static_public_key FROM trusted_devices WHERE device_id=?1",
                [&device_id[..]],
                |r| r.get(0),
            )
            .optional()?;
        let by_key: Option<Vec<u8>> = tx
            .query_row(
                "SELECT device_id FROM trusted_devices WHERE static_public_key=?1",
                [&public_key[..]],
                |r| r.get(0),
            )
            .optional()?;
        if by_id.as_deref().is_some_and(|k| k != public_key)
            || by_key.as_deref().is_some_and(|id| id != device_id)
        {
            return Err(TrustError::KeyConflict);
        }
        if by_id.is_some() {
            return Err(TrustError::KeyConflict);
        }
        let record_id = Uuid::new_v4();
        let trusted_at = now();
        tx.execute(
            "INSERT INTO trusted_devices VALUES(?1,?2,?3,?4,?5,?6,'trusted')",
            params![
                record_id.to_string(),
                &device_id[..],
                &public_key[..],
                label,
                min_protocol,
                trusted_at
            ],
        )?;
        tx.commit()?;
        Ok(TrustedDevice {
            record_id,
            device_id,
            public_key,
            label: label.to_owned(),
            minimum_protocol: min_protocol,
            trusted_at,
            status: TrustStatus::Trusted,
        })
    }
    pub fn authorize_application_data(
        &self,
        device_id: &[u8; 32],
        public_key: &[u8; 32],
        protocol: u16,
    ) -> Result<TrustedDevice, TrustError> {
        let conn = self.connection.lock().expect("trust db poisoned");
        if conn
            .query_row(
                "SELECT 1 FROM revoked_devices WHERE device_id=?1",
                [&device_id[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(TrustError::Revoked);
        }
        let row = conn.query_row("SELECT record_id,device_id,static_public_key,local_label,minimum_protocol,trusted_at,status FROM trusted_devices WHERE device_id=?1", [&device_id[..]], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,String>(3)?,r.get::<_,u16>(4)?,r.get::<_,i64>(5)?,r.get::<_,String>(6)?))).optional()?.ok_or(TrustError::Untrusted)?;
        if row.6 != "trusted" {
            return Err(TrustError::NeedsRepair);
        }
        let stored_id: [u8; 32] = row.1.try_into().map_err(|_| TrustError::InvalidIdentity)?;
        let stored_key: [u8; 32] = row.2.try_into().map_err(|_| TrustError::InvalidIdentity)?;
        if stored_id != *device_id || stored_key != *public_key {
            return Err(TrustError::KeyConflict);
        }
        if protocol < row.4 {
            return Err(TrustError::Untrusted);
        }
        Ok(TrustedDevice {
            record_id: Uuid::parse_str(&row.0).map_err(|_| TrustError::InvalidIdentity)?,
            device_id: stored_id,
            public_key: stored_key,
            label: row.3,
            minimum_protocol: row.4,
            trusted_at: row.5,
            status: TrustStatus::Trusted,
        })
    }
    /// Authorizes and registers while holding the database lock; revocation uses the same lock.
    pub fn authorize_session(
        &self,
        device_id: &[u8; 32],
        public_key: &[u8; 32],
        protocol: u16,
    ) -> Result<(TrustedDevice, ActiveSession), TrustError> {
        let conn = self.connection.lock().expect("trust db poisoned");
        let trusted = authorize_locked(&conn, device_id, public_key, protocol)?;
        let active = self.sessions.register(*device_id);
        Ok((trusted, active))
    }
    pub(crate) fn mark_needs_repair(&self, device_id: &[u8; 32]) -> Result<(), TrustError> {
        let conn = self.connection.lock().expect("trust db poisoned");
        conn.execute(
            "UPDATE trusted_devices SET status='needs_repair' WHERE device_id=?1",
            [&device_id[..]],
        )?;
        self.sessions.terminate(device_id);
        Ok(())
    }
    /// Denylist and deactivate are atomic; failure deleting secure-store material is a separate caller concern.
    pub fn revoke(
        &self,
        device_id: [u8; 32],
        public_key: [u8; 32],
        reason: RevocationReason,
    ) -> Result<(), TrustError> {
        if *blake3::hash(&public_key).as_bytes() != device_id {
            return Err(TrustError::InvalidIdentity);
        }
        let mut conn = self.connection.lock().expect("trust db poisoned");
        let tx = conn.transaction()?;
        tx.execute("INSERT INTO revoked_devices(device_id,static_public_key,revoked_at,reason_code) VALUES(?1,?2,?3,?4) ON CONFLICT(device_id) DO UPDATE SET static_public_key=excluded.static_public_key,revoked_at=excluded.revoked_at,reason_code=excluded.reason_code", params![&device_id[..],&public_key[..],now(),reason.code()])?;
        tx.execute(
            "DELETE FROM trusted_devices WHERE device_id=?1",
            [&device_id[..]],
        )?;
        tx.commit()?;
        self.sessions.terminate(&device_id);
        Ok(())
    }
    pub fn is_revoked(&self, device_id: &[u8; 32]) -> Result<bool, TrustError> {
        let conn = self.connection.lock().expect("trust db poisoned");
        Ok(conn
            .query_row(
                "SELECT 1 FROM revoked_devices WHERE device_id=?1",
                [&device_id[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn authorize_locked(
    conn: &Connection,
    device_id: &[u8; 32],
    public_key: &[u8; 32],
    protocol: u16,
) -> Result<TrustedDevice, TrustError> {
    if conn
        .query_row(
            "SELECT 1 FROM revoked_devices WHERE device_id=?1",
            [&device_id[..]],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Err(TrustError::Revoked);
    }
    let row = conn.query_row(
        "SELECT record_id,device_id,static_public_key,local_label,minimum_protocol,trusted_at,status FROM trusted_devices WHERE device_id=?1",
        [&device_id[..]],
        |r| Ok((r.get::<_, String>(0)?,r.get::<_, Vec<u8>>(1)?,r.get::<_, Vec<u8>>(2)?,r.get::<_, String>(3)?,r.get::<_, u16>(4)?,r.get::<_, i64>(5)?,r.get::<_, String>(6)?)),
    ).optional()?.ok_or(TrustError::Untrusted)?;
    if row.6 != "trusted" {
        return Err(TrustError::NeedsRepair);
    }
    let stored_id: [u8; 32] = row.1.try_into().map_err(|_| TrustError::InvalidIdentity)?;
    let stored_key: [u8; 32] = row.2.try_into().map_err(|_| TrustError::InvalidIdentity)?;
    if stored_id != *device_id || stored_key != *public_key {
        return Err(TrustError::KeyConflict);
    }
    if protocol < row.4 {
        return Err(TrustError::Untrusted);
    }
    Ok(TrustedDevice {
        record_id: Uuid::parse_str(&row.0).map_err(|_| TrustError::InvalidIdentity)?,
        device_id: stored_id,
        public_key: stored_key,
        label: row.3,
        minimum_protocol: row.4,
        trusted_at: row.5,
        status: TrustStatus::Trusted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer() -> ([u8; 32], [u8; 32]) {
        let id = crate::identity::DeviceIdentity::generate().unwrap();
        (id.device_id(), *id.public_key())
    }
    #[test]
    fn trusted_data_requires_exact_key_and_revocation_terminates_sessions() {
        let db = TrustDb::in_memory().unwrap();
        let (id, key) = peer();
        db.commit_trust(id, key, "laptop", 1).unwrap();
        let (_, live) = db.authorize_session(&id, &key, 1).unwrap();
        db.revoke(id, key, RevocationReason::UserRequested).unwrap();
        assert!(!live.is_active());
        assert!(matches!(
            live.ensure_active(),
            Err(TrustError::SessionRevoked)
        ));
        assert!(matches!(
            db.authorize_application_data(&id, &key, 1),
            Err(TrustError::Revoked)
        ));
    }
    #[test]
    fn repair_rows_are_inactive_and_labels_are_not_identity() {
        let db = TrustDb::in_memory().unwrap();
        let (id, key) = peer();
        db.commit_trust(id, key, "same name", 1).unwrap();
        db.mark_needs_repair(&id).unwrap();
        assert!(matches!(
            db.authorize_application_data(&id, &key, 1),
            Err(TrustError::NeedsRepair)
        ));
        let (other_id, other_key) = peer();
        assert_ne!(id, other_id);
        db.commit_trust(other_id, other_key, "same name", 1)
            .unwrap();
    }

    #[test]
    fn trust_and_revocation_survive_database_reopen() {
        let path = std::env::temp_dir().join(format!("clipcore-trust-{}.sqlite", Uuid::new_v4()));
        let (id, key) = peer();
        {
            let db = TrustDb::open(&path).unwrap();
            db.commit_trust(id, key, "local label", 1).unwrap();
        }
        {
            let db = TrustDb::open(&path).unwrap();
            assert!(db.authorize_application_data(&id, &key, 1).is_ok());
            db.revoke(id, key, RevocationReason::StalePairing).unwrap();
        }
        {
            let db = TrustDb::open(&path).unwrap();
            assert!(db.is_revoked(&id).unwrap());
            assert!(matches!(
                db.authorize_application_data(&id, &key, 1),
                Err(TrustError::Revoked)
            ));
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
