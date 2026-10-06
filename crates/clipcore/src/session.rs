use crate::{CURRENT_PROTOCOL_VERSION, identity::DeviceIdentity, protocol::TextEnvelope};
use anyhow::{Result, bail, ensure};
use snow::{HandshakeState, TransportState};
use std::io::{Read, Write};
use std::net::TcpStream;

const NOISE_NAME: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_FRAME: usize = 65_535;

/// Opaque result of the QR-bound pairing handshake. Its fields cannot be forged by callers.
pub struct PairingHandshake {
    pub(crate) state: TransportState,
    pub(crate) remote_static: [u8; 32],
    pub(crate) hash: [u8; 32],
    pub(crate) role: crate::pairing::Role,
    pub(crate) nonce: [u8; 16],
    pub(crate) issuer_key_verified: bool,
}
impl PairingHandshake {
    pub fn transport_mut(&mut self) -> &mut TransportState {
        &mut self.state
    }
    pub fn remote_static(&self) -> &[u8; 32] {
        &self.remote_static
    }
    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.hash
    }
    pub fn role(&self) -> crate::pairing::Role {
        self.role
    }
}

pub fn noise_params() -> Result<snow::params::NoiseParams> {
    Ok(NOISE_NAME.parse()?)
}

fn prologue(version: u16) -> Vec<u8> {
    format!("ClipBridge|Noise-XX|application-envelope-v1|protocol={version}").into_bytes()
}

pub fn validate_version(version: u16) -> Result<()> {
    ensure!(
        version == CURRENT_PROTOCOL_VERSION,
        "unsupported protocol version {version}"
    );
    Ok(())
}

fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX_NOISE_FRAME, "frame exceeds limit");
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut size = [0u8; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(size > 0 && size <= MAX_NOISE_FRAME, "invalid frame size");
    let mut data = vec![0; size];
    stream.read_exact(&mut data)?;
    Ok(data)
}

fn handshake_write(state: &mut HandshakeState, stream: &mut TcpStream) -> Result<()> {
    let mut buf = vec![0; 1024];
    let len = state.write_message(&[], &mut buf)?;
    write_frame(stream, &buf[..len])
}

fn handshake_read(state: &mut HandshakeState, stream: &mut TcpStream) -> Result<()> {
    let frame = read_frame(stream)?;
    let mut payload = vec![0; 1024];
    state.read_message(&frame, &mut payload)?;
    Ok(())
}

pub fn establish(
    stream: &mut TcpStream,
    identity: &DeviceIdentity,
    expected_peer_fingerprint: &str,
    initiator: bool,
    version: u16,
) -> Result<TransportState> {
    validate_version(version)?;
    let params = noise_params()?;
    let mut state = if initiator {
        snow::Builder::new(params)
            .local_private_key(identity.private_key())?
            .prologue(&prologue(version))?
            .build_initiator()?
    } else {
        snow::Builder::new(params)
            .local_private_key(identity.private_key())?
            .prologue(&prologue(version))?
            .build_responder()?
    };
    if initiator {
        handshake_write(&mut state, stream)?;
        handshake_read(&mut state, stream)?;
        handshake_write(&mut state, stream)?;
    } else {
        handshake_read(&mut state, stream)?;
        handshake_write(&mut state, stream)?;
        handshake_read(&mut state, stream)?;
    }
    let remote = state
        .get_remote_static()
        .ok_or_else(|| anyhow::anyhow!("peer omitted static identity"))?;
    let remote_fingerprint = blake3::hash(remote).to_hex().to_string();
    if remote_fingerprint != expected_peer_fingerprint {
        bail!("untrusted peer fingerprint: {remote_fingerprint}");
    }
    Ok(state.into_transport_mode()?)
}

/// Pairing Noise XX uses invitation-bound prologue; the joiner verifies issuer static against QR.
pub fn establish_pairing(
    stream: &mut TcpStream,
    identity: &DeviceIdentity,
    qr: &crate::qr::PairingQr,
    initiator: bool,
    version: u16,
) -> Result<PairingHandshake> {
    validate_version(version)?;
    let prologue = crate::pairing::pairing_prologue(qr.nonce, qr.schema_version(), version)?;
    let mut state = if initiator {
        snow::Builder::new(noise_params()?)
            .local_private_key(identity.private_key())?
            .prologue(&prologue)?
            .build_initiator()?
    } else {
        snow::Builder::new(noise_params()?)
            .local_private_key(identity.private_key())?
            .prologue(&prologue)?
            .build_responder()?
    };
    if initiator {
        handshake_write(&mut state, stream)?;
        handshake_read(&mut state, stream)?;
        handshake_write(&mut state, stream)?;
    } else {
        handshake_read(&mut state, stream)?;
        handshake_write(&mut state, stream)?;
        handshake_read(&mut state, stream)?;
    }
    let remote: [u8; 32] = state
        .get_remote_static()
        .ok_or_else(|| anyhow::anyhow!("peer omitted static identity"))?
        .try_into()?;
    let issuer_key_verified = if initiator {
        crate::pairing::verify_issuer_static(qr, &remote)?;
        true
    } else {
        if identity.public_key() != &qr.issuer_public_key {
            return Err(crate::pairing::PairingError::WrongIssuer.into());
        }
        false
    };
    anyhow::ensure!(
        *blake3::hash(&qr.issuer_public_key).as_bytes() == qr.device_id,
        "invalid QR device ID"
    );
    let hash: [u8; 32] = state.get_handshake_hash().try_into()?;
    Ok(PairingHandshake {
        state: state.into_transport_mode()?,
        remote_static: remote,
        hash,
        role: if initiator {
            crate::pairing::Role::Joiner
        } else {
            crate::pairing::Role::Issuer
        },
        nonce: qr.nonce,
        issuer_key_verified,
    })
}

/// Encrypts a typed PAIR_CONFIRM/PAIR_ACK in the established Noise session.
pub fn send_pair_control(
    stream: &mut TcpStream,
    state: &mut TransportState,
    control: &crate::pairing::PairControl,
    sequence: u64,
) -> Result<()> {
    use crate::pairing::{ControlKind, Role};
    let kind = match control.kind {
        ControlKind::PairConfirm => 2,
        ControlKind::PairAck => 3,
    };
    let role = match control.sender_role {
        Role::Issuer => 0,
        Role::Joiner => 1,
    };
    anyhow::ensure!(
        control.sas.len() == 19 && crate::pairing::sas(&control.handshake_hash)? == control.sas,
        "invalid pairing SAS binding"
    );
    let mut payload = Vec::with_capacity(135);
    payload.extend_from_slice(&control.nonce);
    payload.push(control.qr_schema as u8);
    payload.push(role);
    payload.extend_from_slice(&control.sender_device_id);
    payload.extend_from_slice(&control.receiver_device_id);
    payload.extend_from_slice(&control.handshake_hash);
    payload.extend_from_slice(control.sas.as_bytes());
    payload.extend_from_slice(&control.protocol.to_be_bytes());
    let mut envelope = Vec::with_capacity(35 + payload.len());
    envelope.extend_from_slice(crate::protocol::ENVELOPE_MAGIC);
    envelope.extend_from_slice(&CURRENT_PROTOCOL_VERSION.to_be_bytes());
    envelope.push(kind);
    envelope.extend_from_slice(&sequence.to_be_bytes());
    let mut id = [0; 16];
    getrandom::fill(&mut id)?;
    envelope.extend_from_slice(&id);
    envelope.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&payload);
    let mut ciphertext = vec![0; envelope.len() + 64];
    let n = state.write_message(&envelope, &mut ciphertext)?;
    write_frame(stream, &ciphertext[..n])
}

/// Returns a non-constructible token only after Noise decryption, envelope and control validation.
pub fn receive_pair_control(
    stream: &mut TcpStream,
    state: &mut TransportState,
    expected_sequence: u64,
) -> Result<crate::pairing::AuthenticatedControl> {
    use crate::pairing::AuthenticatedControl;
    let ciphertext = read_frame(stream)?;
    let mut plain = vec![0; MAX_NOISE_FRAME];
    let n = state.read_message(&ciphertext, &mut plain)?;
    let p = &plain[..n];
    anyhow::ensure!(p.len() == 35 + 135, "invalid pairing control length");
    anyhow::ensure!(
        &p[..4] == crate::protocol::ENVELOPE_MAGIC,
        "invalid envelope magic"
    );
    let version = u16::from_be_bytes([p[4], p[5]]);
    validate_version(version)?;
    let seq = u64::from_be_bytes(p[7..15].try_into()?);
    anyhow::ensure!(seq == expected_sequence, "replayed or out-of-order message");
    let payload_len = u32::from_be_bytes(p[31..35].try_into()?) as usize;
    anyhow::ensure!(
        payload_len == 135 && p.len() == 35 + payload_len,
        "invalid pairing control payload length"
    );
    let control = crate::pairing::parse_pair_control(p[6], &p[35..])?;
    Ok(AuthenticatedControl::new(control))
}

pub fn send_text(
    stream: &mut TcpStream,
    state: &mut TransportState,
    envelope: &TextEnvelope,
) -> Result<()> {
    let plaintext = envelope.encode()?;
    let mut ciphertext = vec![0; plaintext.len() + 64];
    let len = state.write_message(&plaintext, &mut ciphertext)?;
    write_frame(stream, &ciphertext[..len])
}

pub fn receive_text(
    stream: &mut TcpStream,
    state: &mut TransportState,
    expected_sequence: u64,
) -> Result<TextEnvelope> {
    let ciphertext = read_frame(stream)?;
    let mut plaintext = vec![0; MAX_NOISE_FRAME];
    let len = state.read_message(&ciphertext, &mut plaintext)?;
    let envelope = TextEnvelope::decode(&plaintext[..len])?;
    ensure!(
        envelope.sequence == expected_sequence,
        "replayed or out-of-order message"
    );
    Ok(envelope)
}

/// Authorized application-data wrappers consult the revocation hook at both sides of I/O.
pub fn send_trusted_text(
    stream: &mut TcpStream,
    state: &mut TransportState,
    envelope: &TextEnvelope,
    active: &crate::trust::ActiveSession,
) -> Result<()> {
    active.ensure_active()?;
    send_text(stream, state, envelope)?;
    active.ensure_active()?;
    Ok(())
}

pub fn receive_trusted_text(
    stream: &mut TcpStream,
    state: &mut TransportState,
    expected_sequence: u64,
    active: &crate::trust::ActiveSession,
) -> Result<TextEnvelope> {
    active.ensure_active()?;
    let envelope = receive_text(stream, state, expected_sequence)?;
    active.ensure_active()?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn version_is_fixed_and_old_versions_fail_closed() {
        assert!(validate_version(CURRENT_PROTOCOL_VERSION).is_ok());
        assert!(validate_version(0).is_err());
        assert!(validate_version(CURRENT_PROTOCOL_VERSION + 1).is_err());
    }

    fn make_session() -> (TcpStream, TransportState, TcpStream, TransportState) {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_a = a.fingerprint();
        let expected_b = b.fingerprint();
        let (tx, rx) = std::sync::mpsc::channel();
        let responder = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let transport = establish(&mut socket, &b, &expected_a, false, 1).unwrap();
            tx.send((socket, transport)).unwrap();
        });
        let mut initiator_socket = TcpStream::connect(addr).unwrap();
        let initiator_transport =
            establish(&mut initiator_socket, &a, &expected_b, true, 1).unwrap();
        responder.join().unwrap();
        let (responder_socket, responder_transport) = rx.recv().unwrap();
        (
            initiator_socket,
            initiator_transport,
            responder_socket,
            responder_transport,
        )
    }

    #[test]
    fn encrypted_record_tampering_is_rejected() {
        let (mut sender, mut tx, mut receiver, mut rx) = make_session();
        let message = TextEnvelope::new(0, [1; 16], b"authenticated".to_vec())
            .unwrap()
            .encode()
            .unwrap();
        let mut ciphertext = vec![0; message.len() + 64];
        let len = tx.write_message(&message, &mut ciphertext).unwrap();
        ciphertext[len - 1] ^= 1;
        write_frame(&mut sender, &ciphertext[..len]).unwrap();
        assert!(receive_text(&mut receiver, &mut rx, 0).is_err());
    }

    #[test]
    fn replayed_ciphertext_is_rejected() {
        let (mut sender, mut tx, mut receiver, mut rx) = make_session();
        let message = TextEnvelope::new(0, [2; 16], b"once only".to_vec())
            .unwrap()
            .encode()
            .unwrap();
        let mut ciphertext = vec![0; message.len() + 64];
        let len = tx.write_message(&message, &mut ciphertext).unwrap();
        let record = ciphertext[..len].to_vec();
        write_frame(&mut sender, &record).unwrap();
        assert_eq!(
            receive_text(&mut receiver, &mut rx, 0).unwrap().text,
            b"once only"
        );
        write_frame(&mut sender, &record).unwrap();
        assert!(receive_text(&mut receiver, &mut rx, 1).is_err());
    }

    #[test]
    fn authenticated_duplicate_sequence_is_rejected() {
        let (mut sender, mut tx, mut receiver, mut rx) = make_session();
        for id in [4u8, 5u8] {
            let message = TextEnvelope::new(0, [id; 16], b"same logical sequence".to_vec())
                .unwrap()
                .encode()
                .unwrap();
            let mut ciphertext = vec![0; message.len() + 64];
            let len = tx.write_message(&message, &mut ciphertext).unwrap();
            write_frame(&mut sender, &ciphertext[..len]).unwrap();
            let result = receive_text(&mut receiver, &mut rx, if id == 4 { 0 } else { 1 });
            if id == 4 {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn qr_paired_processes_exchange_authenticated_confirmation_and_ack() {
        use crate::{
            pairing::{InvitationIssuer, PairingTransaction},
            trust::TrustDb,
        };
        use std::time::Duration;
        let issuer = DeviceIdentity::generate().unwrap();
        let joiner = DeviceIdentity::generate().unwrap();
        let issuer_id = issuer.device_id();
        let issuer_key = *issuer.public_key();
        let joiner_id = joiner.device_id();
        let joiner_key = *joiner.public_key();
        let mut invitation = InvitationIssuer::default();
        let (qr, _) = invitation.issue(Duration::ZERO, &issuer, vec![]).unwrap();
        invitation.start(Duration::from_secs(1), qr.nonce).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let issuer_qr = qr.clone();
        let issuer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut handshake =
                establish_pairing(&mut stream, &issuer, &issuer_qr, false, 1).unwrap();
            let mut pairing =
                PairingTransaction::from_verified_handshake(&issuer, &handshake, "joiner".into());
            let local_confirm = pairing.confirm_local(true).unwrap();
            let remote_confirm =
                receive_pair_control(&mut stream, handshake.transport_mut(), 0).unwrap();
            pairing.receive_confirm(&remote_confirm).unwrap();
            send_pair_control(&mut stream, handshake.transport_mut(), &local_confirm, 0).unwrap();
            let local_ack = pairing.make_ack().unwrap();
            let remote_ack =
                receive_pair_control(&mut stream, handshake.transport_mut(), 1).unwrap();
            pairing.receive_ack(&remote_ack).unwrap();
            send_pair_control(&mut stream, handshake.transport_mut(), &local_ack, 1).unwrap();
            let db = TrustDb::in_memory().unwrap();
            pairing.commit_local(&db).unwrap();
            done_tx
                .send(
                    db.authorize_application_data(&joiner_id, &joiner_key, 1)
                        .is_ok(),
                )
                .unwrap();
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let mut handshake = establish_pairing(&mut stream, &joiner, &qr, true, 1).unwrap();
        let mut pairing =
            PairingTransaction::from_verified_handshake(&joiner, &handshake, "issuer".into());
        let local_confirm = pairing.confirm_local(true).unwrap();
        send_pair_control(&mut stream, handshake.transport_mut(), &local_confirm, 0).unwrap();
        let remote_confirm =
            receive_pair_control(&mut stream, handshake.transport_mut(), 0).unwrap();
        pairing.receive_confirm(&remote_confirm).unwrap();
        let local_ack = pairing.make_ack().unwrap();
        send_pair_control(&mut stream, handshake.transport_mut(), &local_ack, 1).unwrap();
        let remote_ack = receive_pair_control(&mut stream, handshake.transport_mut(), 1).unwrap();
        pairing.receive_ack(&remote_ack).unwrap();
        let db = TrustDb::in_memory().unwrap();
        pairing.commit_local(&db).unwrap();
        assert!(
            db.authorize_application_data(&issuer_id, &issuer_key, 1)
                .is_ok()
        );
        assert!(done_rx.recv().unwrap());
        issuer_thread.join().unwrap();
    }
}
