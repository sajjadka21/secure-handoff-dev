#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = if let Some(hex) = data.strip_prefix(b"HEX:") {
        if hex.len() % 2 != 0 || hex.len() > 1024 {
            return;
        }
        let mut out = Vec::with_capacity(hex.len() / 2);
        for pair in hex.chunks_exact(2) {
            let digit = |v: u8| match v {
                b'0'..=b'9' => Some(v - b'0'),
                b'a'..=b'f' => Some(v - b'a' + 10),
                b'A'..=b'F' => Some(v - b'A' + 10),
                _ => None,
            };
            let Some(hi) = digit(pair[0]) else {
                return;
            };
            let Some(lo) = digit(pair[1]) else {
                return;
            };
            out.push((hi << 4) | lo);
        }
        out
    } else {
        data.to_vec()
    };
    let _ = clipcore::qr::PairingQr::decode(&input);
});
