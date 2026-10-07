//! Phase-1 TCP/LAN transport boundary. Later routes implement this same contract.
use anyhow::{Result, ensure};
use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

pub trait SecureTransport {
    fn connect(&self, peer: SocketAddr) -> Result<TcpStream>;
    fn listen(&self, bind: SocketAddr) -> Result<TcpListener>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LanTcp;

impl SecureTransport for LanTcp {
    fn connect(&self, peer: SocketAddr) -> Result<TcpStream> {
        Ok(TcpStream::connect(peer)?)
    }
    fn listen(&self, bind: SocketAddr) -> Result<TcpListener> {
        Ok(TcpListener::bind(bind)?)
    }
}

/// An authenticated LAN session. Constructing this value checks the peer against local trust;
/// discovery and a successful Noise handshake by themselves cannot create one.
pub struct TrustedLanSession {
    stream: TcpStream,
    state: snow::TransportState,
    peer_id: [u8; 32],
    protocol: u16,
    active: crate::trust::ActiveSession,
}

impl TrustedLanSession {
    pub fn connect(
        address: SocketAddr,
        identity: &crate::identity::DeviceIdentity,
        expected_device_id: [u8; 32],
        trust: &crate::trust::TrustDb,
        protocol: u16,
    ) -> Result<Self> {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(8))?;
        Self::from_stream(
            &mut stream,
            identity,
            trust,
            protocol,
            true,
            Some(expected_device_id),
        )
        .map(|mut session| {
            session.stream = stream;
            session
        })
    }

    pub fn accept(
        mut stream: TcpStream,
        identity: &crate::identity::DeviceIdentity,
        trust: &crate::trust::TrustDb,
        protocol: u16,
    ) -> Result<Self> {
        Self::from_stream(&mut stream, identity, trust, protocol, false, None)
    }

    fn from_stream(
        stream: &mut TcpStream,
        identity: &crate::identity::DeviceIdentity,
        trust: &crate::trust::TrustDb,
        protocol: u16,
        initiator: bool,
        expected: Option<[u8; 32]>,
    ) -> Result<Self> {
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        stream.set_write_timeout(Some(Duration::from_secs(15)))?;
        stream.set_nodelay(true)?;
        let candidate = crate::session::establish_candidate(stream, identity, initiator, protocol)?;
        let peer_id = *blake3::hash(&candidate.remote_static).as_bytes();
        if let Some(expected) = expected {
            ensure!(peer_id == expected, "identity_mismatch");
        }
        let (_, active) = trust.authorize_session(&peer_id, &candidate.remote_static, protocol)?;
        Ok(Self {
            stream: stream.try_clone()?,
            state: candidate.state,
            peer_id,
            protocol,
            active,
        })
    }

    pub fn peer_id(&self) -> &[u8; 32] {
        &self.peer_id
    }

    pub fn send_text(&mut self, sequence: u64, text: Vec<u8>) -> Result<()> {
        self.active.ensure_active()?;
        let mut id = [0; 16];
        getrandom::fill(&mut id)?;
        let envelope = crate::protocol::TextEnvelope::new(sequence, id, text)?;
        crate::session::send_trusted_text(
            &mut self.stream,
            &mut self.state,
            &envelope,
            &self.active,
        )
    }

    pub fn receive_text(&mut self, sequence: u64) -> Result<crate::protocol::TextEnvelope> {
        self.active.ensure_active()?;
        let envelope = crate::session::receive_trusted_text(
            &mut self.stream,
            &mut self.state,
            sequence,
            &self.active,
        )?;
        ensure!(
            self.protocol == crate::CURRENT_PROTOCOL_VERSION,
            "protocol_incompatible"
        );
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::DeviceIdentity,
        trust::{RevocationReason, TrustDb},
    };

    fn trust_peer(db: &TrustDb, peer: &DeviceIdentity) {
        db.commit_trust(peer.device_id(), *peer.public_key(), "test peer", 1)
            .unwrap();
    }

    #[test]
    fn trusted_lan_session_exchanges_text_and_revocation_stops_next_io() {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        let a_db = TrustDb::in_memory().unwrap();
        let b_db = TrustDb::in_memory().unwrap();
        trust_peer(&a_db, &b);
        trust_peer(&b_db, &a);
        let listener = LanTcp.listen("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = listener.local_addr().unwrap();
        let b_id = b.device_id();
        let a_id = a.device_id();
        let a_key = *a.public_key();
        let (received_tx, received_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut session = TrustedLanSession::accept(socket, &b, &b_db, 1).unwrap();
            let envelope = session.receive_text(0).unwrap();
            received_tx.send(envelope.text).unwrap();
            b_db.revoke(a_id, a_key, RevocationReason::UserRequested)
                .unwrap();
            assert!(session.receive_text(1).is_err());
        });
        let mut client = TrustedLanSession::connect(address, &a, b_id, &a_db, 1).unwrap();
        client.send_text(0, b"verified transfer".to_vec()).unwrap();
        assert_eq!(received_rx.recv().unwrap(), b"verified transfer");
        server.join().unwrap();
    }
}
