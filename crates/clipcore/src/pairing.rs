//! Pairing invitation lifecycle, transcript-derived SAS, and local bilateral-control state.
use crate::{
    identity::DeviceIdentity,
    qr::{PairingQr, QR_SCHEMA_VERSION},
    trust::{TrustDb, TrustError},
};
use std::{collections::VecDeque, time::Duration};
use thiserror::Error;

pub const INVITATION_LIFETIME: Duration = Duration::from_secs(120);
#[derive(Debug, Error)]
pub enum PairingError {
    #[error("invitation is stale, expired, replayed, or not current")]
    InvalidInvitation,
    #[error("pairing attempt rate limit; retry after cooldown")]
    RateLimited,
    #[error("issuer static key does not match QR")]
    WrongIssuer,
    #[error("pairing transcript or control message mismatch")]
    BindingMismatch,
    #[error("protocol or QR schema version mismatch")]
    VersionMismatch,
    #[error("local SAS confirmation is required first")]
    ConfirmationRequired,
    #[error("peer confirmation must be received before ACK")]
    AckOutOfOrder,
    #[error("pairing is not eligible for local trust commit")]
    NotReady,
    #[error("pairing ended after local trust commit; local trust quarantined")]
    NeedsRepair,
    #[error("trust database rejected pairing")]
    Trust(#[from] TrustError),
}

#[derive(Clone)]
struct Invitation {
    nonce: [u8; 16],
    issued_at: Duration,
    consumed: bool,
}
#[derive(Default)]
pub struct InvitationIssuer {
    current: Option<Invitation>,
    starts: VecDeque<Duration>,
    cooldown_until: Option<Duration>,
}
impl InvitationIssuer {
    /// Invalidates the current volatile invitation immediately.
    pub fn cancel(&mut self) {
        self.current = None;
    }
    pub fn issue(
        &mut self,
        now: Duration,
        identity: &DeviceIdentity,
        endpoints: Vec<String>,
    ) -> Result<(PairingQr, Vec<u8>), PairingError> {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| PairingError::InvalidInvitation)?;
        let qr = PairingQr {
            issuer_public_key: *identity.public_key(),
            device_id: identity.device_id(),
            nonce,
            endpoints,
        };
        let bytes = qr.encode().map_err(|_| PairingError::VersionMismatch)?;
        self.current = Some(Invitation {
            nonce,
            issued_at: now,
            consumed: false,
        });
        Ok((qr, bytes))
    }
    pub fn start(&mut self, now: Duration, nonce: [u8; 16]) -> Result<(), PairingError> {
        if self.cooldown_until.is_some_and(|until| now < until) {
            return Err(PairingError::RateLimited);
        }
        if self.cooldown_until.is_some() {
            self.cooldown_until = None;
            self.starts.clear()
        }
        while self
            .starts
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= Duration::from_secs(60))
        {
            self.starts.pop_front();
        }
        if self.starts.len() >= 5 {
            self.cooldown_until = Some(now + Duration::from_secs(60));
            return Err(PairingError::RateLimited);
        }
        self.starts.push_back(now);
        let invite = self
            .current
            .as_mut()
            .ok_or(PairingError::InvalidInvitation)?;
        if invite.consumed
            || invite.nonce != nonce
            || now.saturating_sub(invite.issued_at) > INVITATION_LIFETIME
        {
            return Err(PairingError::InvalidInvitation);
        }
        invite.consumed = true;
        Ok(())
    }
}

pub fn pairing_prologue(
    nonce: [u8; 16],
    qr_schema: u64,
    protocol: u16,
) -> Result<Vec<u8>, PairingError> {
    if qr_schema != QR_SCHEMA_VERSION || protocol != crate::CURRENT_PROTOCOL_VERSION {
        return Err(PairingError::VersionMismatch);
    }
    let mut out=format!("ClipBridge-Pairing|Noise_XX_25519_ChaChaPoly_BLAKE2s|application-envelope=1|wire={protocol}|qr={qr_schema}|nonce=").into_bytes();
    out.extend_from_slice(&nonce);
    Ok(out)
}

pub fn verify_issuer_static(
    qr: &PairingQr,
    authenticated_remote_static: &[u8],
) -> Result<(), PairingError> {
    if authenticated_remote_static == qr.issuer_public_key {
        Ok(())
    } else {
        Err(PairingError::WrongIssuer)
    }
}

/// Display-only value; never used as key material.
pub fn sas(handshake_hash: &[u8]) -> Result<String, PairingError> {
    if handshake_hash.len() < 8 {
        return Err(PairingError::BindingMismatch);
    }
    let first = u64::from_be_bytes(
        handshake_hash[..8]
            .try_into()
            .map_err(|_| PairingError::BindingMismatch)?,
    );
    let hex = format!("{first:016x}");
    Ok(format!(
        "{}-{}-{}-{}",
        &hex[0..4],
        &hex[4..8],
        &hex[8..12],
        &hex[12..16]
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Issuer,
    Joiner,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    InvitationIssued,
    Handshake,
    SasPending,
    LocalConfirmed,
    ConfirmExchanged,
    AckExchanged,
    LocallyCommitted,
    PairingCompleteHere,
    NeedsRepair,
    Aborted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlKind {
    PairConfirm,
    PairAck,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairControl {
    pub(crate) kind: ControlKind,
    pub(crate) nonce: [u8; 16],
    pub(crate) qr_schema: u64,
    pub(crate) sender_role: Role,
    pub(crate) sender_device_id: [u8; 32],
    pub(crate) receiver_device_id: [u8; 32],
    pub(crate) handshake_hash: [u8; 32],
    pub(crate) sas: String,
    pub(crate) protocol: u16,
}
/// Constructed only by session code after Noise AEAD verification.
pub struct AuthenticatedControl {
    control: PairControl,
}
impl AuthenticatedControl {
    pub(crate) fn new(control: PairControl) -> Self {
        Self { control }
    }
}

/// Parses a fixed-size control payload. This does not authenticate it; callers must pass a
/// successfully Noise-decrypted result through the session layer before state transitions.
pub fn parse_pair_control(kind_byte: u8, b: &[u8]) -> Result<PairControl, PairingError> {
    if b.len() != 135 {
        return Err(PairingError::BindingMismatch);
    }
    let kind = match kind_byte {
        2 => ControlKind::PairConfirm,
        3 => ControlKind::PairAck,
        _ => return Err(PairingError::BindingMismatch),
    };
    let nonce = b[..16]
        .try_into()
        .map_err(|_| PairingError::BindingMismatch)?;
    let qr_schema = b[16] as u64;
    if qr_schema != QR_SCHEMA_VERSION {
        return Err(PairingError::VersionMismatch);
    }
    let sender_role = match b[17] {
        0 => Role::Issuer,
        1 => Role::Joiner,
        _ => return Err(PairingError::BindingMismatch),
    };
    let sender_device_id = b[18..50]
        .try_into()
        .map_err(|_| PairingError::BindingMismatch)?;
    let receiver_device_id = b[50..82]
        .try_into()
        .map_err(|_| PairingError::BindingMismatch)?;
    let handshake_hash: [u8; 32] = b[82..114]
        .try_into()
        .map_err(|_| PairingError::BindingMismatch)?;
    let sas_value = std::str::from_utf8(&b[114..133])
        .map_err(|_| PairingError::BindingMismatch)?
        .to_owned();
    if sas(&handshake_hash).map_err(|_| PairingError::BindingMismatch)? != sas_value {
        return Err(PairingError::BindingMismatch);
    }
    let protocol = u16::from_be_bytes(
        b[133..135]
            .try_into()
            .map_err(|_| PairingError::BindingMismatch)?,
    );
    if protocol != crate::CURRENT_PROTOCOL_VERSION {
        return Err(PairingError::VersionMismatch);
    }
    Ok(PairControl {
        kind,
        nonce,
        qr_schema,
        sender_role,
        sender_device_id,
        receiver_device_id,
        handshake_hash,
        sas: sas_value,
        protocol,
    })
}

pub struct PairingTransaction {
    pub state: State,
    pub role: Role,
    local_id: [u8; 32],
    peer_id: [u8; 32],
    nonce: [u8; 16],
    handshake_hash: [u8; 32],
    sas: String,
    local_confirmed: bool,
    peer_confirmed: bool,
    peer_ack: bool,
    issuer_key_verified: bool,
    peer_key: [u8; 32],
    label: String,
    min_protocol: u16,
}
impl PairingTransaction {
    /// Creates pairing state only from the opaque result of a QR-bound Noise XX handshake.
    pub fn from_verified_handshake(
        local: &DeviceIdentity,
        handshake: &crate::session::PairingHandshake,
        label: String,
    ) -> Self {
        Self::after_handshake(
            handshake.role,
            local,
            handshake.remote_static,
            handshake.nonce,
            handshake.hash,
            handshake.issuer_key_verified,
            label,
        )
    }
    pub(crate) fn after_handshake(
        role: Role,
        local: &DeviceIdentity,
        peer_key: [u8; 32],
        nonce: [u8; 16],
        hash: [u8; 32],
        issuer_key_verified: bool,
        label: String,
    ) -> Self {
        let peer_id = *blake3::hash(&peer_key).as_bytes();
        Self {
            state: State::SasPending,
            role,
            local_id: local.device_id(),
            peer_id,
            nonce,
            handshake_hash: hash,
            sas: sas(&hash).expect("fixed hash"),
            local_confirmed: false,
            peer_confirmed: false,
            peer_ack: false,
            issuer_key_verified,
            peer_key,
            label,
            min_protocol: 1,
        }
    }
    pub fn sas(&self) -> &str {
        &self.sas
    }
    pub fn peer_id(&self) -> &[u8; 32] {
        &self.peer_id
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn confirm_local(&mut self, accept: bool) -> Result<PairControl, PairingError> {
        if self.state != State::SasPending {
            return Err(PairingError::ConfirmationRequired);
        }
        if !accept {
            self.state = State::Aborted;
            return Err(PairingError::BindingMismatch);
        }
        self.local_confirmed = true;
        self.state = State::LocalConfirmed;
        Ok(self.control(ControlKind::PairConfirm))
    }
    pub fn receive_confirm(
        &mut self,
        authenticated: &AuthenticatedControl,
    ) -> Result<(), PairingError> {
        let c = &authenticated.control;
        if c.kind != ControlKind::PairConfirm || !self.local_confirmed {
            return Err(PairingError::ConfirmationRequired);
        }
        self.validate(c)?;
        self.peer_confirmed = true;
        self.state = State::ConfirmExchanged;
        Ok(())
    }
    pub fn make_ack(&mut self) -> Result<PairControl, PairingError> {
        if !self.peer_confirmed {
            return Err(PairingError::AckOutOfOrder);
        }
        Ok(self.control(ControlKind::PairAck))
    }
    pub fn receive_ack(
        &mut self,
        authenticated: &AuthenticatedControl,
    ) -> Result<(), PairingError> {
        let c = &authenticated.control;
        if c.kind != ControlKind::PairAck || !self.peer_confirmed {
            return Err(PairingError::AckOutOfOrder);
        }
        self.validate(c)?;
        self.peer_ack = true;
        self.state = State::AckExchanged;
        Ok(())
    }
    fn validate(&self, c: &PairControl) -> Result<(), PairingError> {
        if c.nonce != self.nonce
            || c.qr_schema != QR_SCHEMA_VERSION
            || c.sender_role == self.role
            || c.sender_device_id != self.peer_id
            || c.receiver_device_id != self.local_id
            || c.handshake_hash != self.handshake_hash
            || c.sas != self.sas
        {
            return Err(PairingError::BindingMismatch);
        }
        if c.protocol != crate::CURRENT_PROTOCOL_VERSION {
            return Err(PairingError::VersionMismatch);
        }
        Ok(())
    }
    fn control(&self, kind: ControlKind) -> PairControl {
        PairControl {
            kind,
            nonce: self.nonce,
            qr_schema: QR_SCHEMA_VERSION,
            sender_role: self.role,
            sender_device_id: self.local_id,
            receiver_device_id: self.peer_id,
            handshake_hash: self.handshake_hash,
            sas: self.sas.clone(),
            protocol: crate::CURRENT_PROTOCOL_VERSION,
        }
    }
    pub fn commit_local(&mut self, db: &TrustDb) -> Result<(), PairingError> {
        if !self.local_confirmed
            || !self.peer_confirmed
            || !self.peer_ack
            || (self.role == Role::Joiner && !self.issuer_key_verified)
        {
            return Err(PairingError::NotReady);
        }
        db.commit_trust(self.peer_id, self.peer_key, &self.label, self.min_protocol)?;
        self.state = State::LocallyCommitted;
        Ok(())
    }
    pub fn complete_here(&mut self) {
        if self.state == State::LocallyCommitted {
            self.state = State::PairingCompleteHere
        }
    }
    pub fn observe_failure(&mut self, db: &TrustDb) -> Result<(), PairingError> {
        if self.state == State::LocallyCommitted || self.state == State::PairingCompleteHere {
            db.mark_needs_repair(&self.peer_id)?;
            self.state = State::NeedsRepair;
            Err(PairingError::NeedsRepair)
        } else {
            self.state = State::Aborted;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identities() -> (DeviceIdentity, DeviceIdentity) {
        (
            DeviceIdentity::generate().unwrap(),
            DeviceIdentity::generate().unwrap(),
        )
    }
    #[test]
    fn invite_is_single_use_expires_and_new_issue_replaces_old() {
        let (a, _) = identities();
        let mut i = InvitationIssuer::default();
        let (q, _) = i.issue(Duration::ZERO, &a, vec![]).unwrap();
        i.start(Duration::from_secs(1), q.nonce).unwrap();
        assert!(matches!(
            i.start(Duration::from_secs(2), q.nonce),
            Err(PairingError::InvalidInvitation)
        ));
        let (q2, _) = i.issue(Duration::from_secs(3), &a, vec![]).unwrap();
        assert!(matches!(
            i.start(Duration::from_secs(3), q.nonce),
            Err(PairingError::InvalidInvitation)
        ));
        assert!(i.start(Duration::from_secs(123), q2.nonce).is_ok());
    }
    #[test]
    fn pairing_throttle_five_per_minute_then_cooldown() {
        let (a, _) = identities();
        let mut i = InvitationIssuer::default();
        for n in 0..5 {
            let (q, _) = i.issue(Duration::from_secs(n), &a, vec![]).unwrap();
            assert!(i.start(Duration::from_secs(n), q.nonce).is_ok());
        }
        let (q, _) = i.issue(Duration::from_secs(5), &a, vec![]).unwrap();
        assert!(matches!(
            i.start(Duration::from_secs(5), q.nonce),
            Err(PairingError::RateLimited)
        ));
        assert!(matches!(
            i.start(Duration::from_secs(64), q.nonce),
            Err(PairingError::RateLimited)
        ));
    }
    #[test]
    fn sas_vector_and_role_independence() {
        let h = [0xabu8; 32];
        assert_eq!(sas(&h).unwrap(), "abab-abab-abab-abab");
        let mut changed = h;
        changed[0] ^= 1;
        assert_ne!(sas(&h).unwrap(), sas(&changed).unwrap());
    }

    #[test]
    fn pairing_control_parser_checks_exact_lengths_versions_and_transcript_sas() {
        let hash = [0xabu8; 32];
        let sas_value = sas(&hash).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[8; 16]);
        bytes.extend_from_slice(&[1, 0]);
        bytes.extend_from_slice(&[2; 32]);
        bytes.extend_from_slice(&[3; 32]);
        bytes.extend_from_slice(&hash);
        bytes.extend_from_slice(sas_value.as_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        assert!(parse_pair_control(2, &bytes).is_ok());
        let mut bad = bytes.clone();
        bad[16] = 2;
        assert!(matches!(
            parse_pair_control(2, &bad),
            Err(PairingError::VersionMismatch)
        ));
        let mut bad = bytes.clone();
        bad[134] = 2;
        assert!(matches!(
            parse_pair_control(2, &bad),
            Err(PairingError::VersionMismatch)
        ));
        let mut bad = bytes.clone();
        bad[114] = b'0';
        assert!(matches!(
            parse_pair_control(2, &bad),
            Err(PairingError::BindingMismatch)
        ));
        assert!(parse_pair_control(2, &bytes[..134]).is_err());
        assert!(parse_pair_control(9, &bytes).is_err());
    }
    #[test]
    fn wrong_issuer_and_nonce_protocol_binding_fail() {
        let (a, b) = identities();
        let qr = PairingQr {
            issuer_public_key: *a.public_key(),
            device_id: a.device_id(),
            nonce: [3; 16],
            endpoints: vec![],
        };
        assert!(matches!(
            verify_issuer_static(&qr, b.public_key()),
            Err(PairingError::WrongIssuer)
        ));
        assert_ne!(
            pairing_prologue([1; 16], 1, 1).unwrap(),
            pairing_prologue([2; 16], 1, 1).unwrap()
        );
        assert!(pairing_prologue([1; 16], 2, 1).is_err());
        assert!(pairing_prologue([1; 16], 1, 0).is_err());
    }
    #[test]
    fn confirmation_ack_order_and_repair_cutpoint() {
        let (a, b) = identities();
        let hash = [55; 32];
        let mut p = PairingTransaction::after_handshake(
            Role::Joiner,
            &a,
            *b.public_key(),
            [1; 16],
            hash,
            true,
            "peer".into(),
        );
        let db = TrustDb::in_memory().unwrap();
        assert!(matches!(p.commit_local(&db), Err(PairingError::NotReady)));
        assert!(matches!(p.make_ack(), Err(PairingError::AckOutOfOrder)));
        let confirm = p.confirm_local(true).unwrap();
        let mut other = PairingTransaction::after_handshake(
            Role::Issuer,
            &b,
            *a.public_key(),
            [1; 16],
            hash,
            true,
            "peer".into(),
        );
        let confirm_other = other.confirm_local(true).unwrap();
        p.receive_confirm(&AuthenticatedControl::new(confirm_other))
            .unwrap();
        other
            .receive_confirm(&AuthenticatedControl::new(confirm))
            .unwrap();
        let ack = other.make_ack().unwrap();
        p.receive_ack(&AuthenticatedControl::new(ack)).unwrap();
        p.commit_local(&db).unwrap();
        assert!(
            db.authorize_application_data(&b.device_id(), b.public_key(), 1)
                .is_ok()
        );
        let peer_without_commit = TrustDb::in_memory().unwrap();
        assert!(matches!(
            peer_without_commit.authorize_application_data(&a.device_id(), a.public_key(), 1),
            Err(TrustError::Untrusted)
        ));
        assert!(matches!(
            p.observe_failure(&db),
            Err(PairingError::NeedsRepair)
        ));
        assert!(matches!(
            db.authorize_application_data(&b.device_id(), b.public_key(), 1),
            Err(TrustError::NeedsRepair)
        ));
    }
    #[test]
    fn unconfirmed_peer_never_gains_trust() {
        let (a, b) = identities();
        let mut p = PairingTransaction::after_handshake(
            Role::Joiner,
            &a,
            *b.public_key(),
            [1; 16],
            [2; 32],
            false,
            "x".into(),
        );
        let db = TrustDb::in_memory().unwrap();
        assert!(matches!(p.commit_local(&db), Err(PairingError::NotReady)));
        assert!(matches!(
            db.authorize_application_data(&b.device_id(), b.public_key(), 1),
            Err(TrustError::Untrusted)
        ));
    }
}
