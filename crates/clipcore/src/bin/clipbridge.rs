//! Phase-1 demo process: generates an ephemeral identity and pins one peer manually.
use anyhow::{Result, bail};
use clipcore::{
    identity::DeviceIdentity,
    protocol::TextEnvelope,
    session,
    transport::{LanTcp, SecureTransport},
};
use std::{
    env,
    io::{self, BufRead, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

fn usage() -> anyhow::Error {
    anyhow::anyhow!(
        "usage: clipbridge listen <bind-addr> <version> | send <peer-addr> <version> <text>; each process prints READY <fingerprint>, then read the other process's fingerprint from stdin after verifying it"
    )
}

fn parse_version(s: &str) -> Result<u16> {
    let v: u16 = s.parse()?;
    session::validate_version(v)?;
    Ok(v)
}

fn confirm_peer_fingerprint() -> Result<String> {
    let mut fingerprint = String::new();
    io::stdin().lock().read_line(&mut fingerprint)?;
    let fingerprint = fingerprint.trim().to_owned();
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("expected a 64-character peer fingerprint on stdin");
    }
    Ok(fingerprint.to_ascii_lowercase())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("clipbridge: {e:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("listen") if args.len() == 4 => {
            let bind: SocketAddr = args[2].parse()?;
            let identity = DeviceIdentity::generate()?;
            let version = parse_version(&args[3])?;
            let listener = LanTcp.listen(bind)?;
            println!("READY {}", identity.fingerprint());
            io::stdout().flush()?;
            let expected = confirm_peer_fingerprint()?;
            let stream = listener.accept()?.0;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut stream = stream;
            let mut cipher = session::establish(&mut stream, &identity, &expected, false, version)?;
            let envelope = session::receive_text(&mut stream, &mut cipher, 0)?;
            println!("RECEIVED {}", String::from_utf8(envelope.text)?);
        }
        Some("send") if args.len() == 5 => {
            let peer: SocketAddr = args[2].parse()?;
            let identity = DeviceIdentity::generate()?;
            let version = parse_version(&args[3])?;
            println!("READY {}", identity.fingerprint());
            io::stdout().flush()?;
            let expected = confirm_peer_fingerprint()?;
            let mut stream: TcpStream = LanTcp.connect(peer)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut cipher = session::establish(&mut stream, &identity, &expected, true, version)?;
            let mut message_id = [0u8; 16];
            getrandom::fill(&mut message_id)?;
            let envelope = TextEnvelope::new(0, message_id, args[4].as_bytes().to_vec())?;
            session::send_text(&mut stream, &mut cipher, &envelope)?;
            println!("SENT");
        }
        _ => bail!(usage()),
    }
    Ok(())
}
