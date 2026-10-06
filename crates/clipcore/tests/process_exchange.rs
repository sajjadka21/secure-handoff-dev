use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

fn launch_listener() -> (Child, ChildStdin, BufReader<ChildStdout>, String) {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    drop(socket);
    let mut child = Command::new(env!("CARGO_BIN_EXE_clipbridge"))
        .args(["listen", &addr.to_string(), "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let fingerprint = ready_fingerprint(&mut stdout);
    // The address is passed back through a test-only marker held by the helper.
    (child, stdin, stdout, format!("{addr}|{fingerprint}"))
}

fn ready_fingerprint(stdout: &mut BufReader<ChildStdout>) -> String {
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let (ready, fingerprint) = line.trim().split_once(' ').unwrap();
    assert_eq!(ready, "READY");
    fingerprint.to_string()
}

fn launch_sender(addr: &str, text: &str) -> (Child, ChildStdin, BufReader<ChildStdout>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_clipbridge"))
        .args(["send", addr, "1", text])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let fingerprint = ready_fingerprint(&mut stdout);
    (child, stdin, stdout, fingerprint)
}

fn give_pin(stdin: &mut ChildStdin, fingerprint: &str) {
    writeln!(stdin, "{fingerprint}").unwrap();
    stdin.flush().unwrap();
}

fn output(
    child: Child,
    mut stdout: BufReader<ChildStdout>,
) -> (std::process::ExitStatus, String, String) {
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    let result = child.wait_with_output().unwrap();
    (
        result.status,
        rest,
        String::from_utf8_lossy(&result.stderr).into_owned(),
    )
}

#[test]
fn separate_processes_generate_identities_pair_and_exchange_text() {
    let (server, mut server_in, server_out, server_info) = launch_listener();
    let (addr, server_fp) = server_info.split_once('|').unwrap();
    let (client, mut client_in, client_out, client_fp) = launch_sender(addr, "phase one message");
    assert_ne!(
        server_fp, client_fp,
        "processes must have distinct generated identities"
    );
    give_pin(&mut server_in, &client_fp);
    give_pin(&mut client_in, server_fp);

    let (client_status, client_out, client_err) = output(client, client_out);
    let (server_status, server_out, server_err) = output(server, server_out);
    assert!(client_status.success(), "{client_err}");
    assert!(client_out.contains("SENT"), "{client_out}");
    assert!(server_status.success(), "{server_err}");
    assert!(
        server_out.contains("RECEIVED phase one message"),
        "{server_out}"
    );
}

#[test]
fn process_rejects_untrusted_peer_fingerprint() {
    let (server, mut server_in, server_out, server_info) = launch_listener();
    let (addr, server_fp) = server_info.split_once('|').unwrap();
    let (client, mut client_in, client_out, client_fp) = launch_sender(addr, "must not arrive");
    give_pin(&mut server_in, &"00".repeat(32));
    give_pin(&mut client_in, server_fp);

    let _ = output(client, client_out);
    let (server_status, server_out, server_err) = output(server, server_out);
    assert!(!server_status.success());
    assert!(
        server_err.contains("untrusted peer fingerprint"),
        "{server_err}"
    );
    assert!(!server_out.contains("RECEIVED"));
    assert_ne!(server_fp, client_fp);
}
