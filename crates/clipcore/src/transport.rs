//! Phase-1 TCP/LAN transport boundary. Later routes implement this same contract.
use anyhow::Result;
use std::net::{SocketAddr, TcpListener, TcpStream};

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
