#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data == b"MAX_VALID_ENVELOPE" {
        if let Ok(value) =
            clipcore::protocol::TextEnvelope::new(0, [0; 16], vec![0; clipcore::MAX_TEXT_BYTES])
        {
            let bytes = value.encode().unwrap();
            let _ = clipcore::protocol::TextEnvelope::decode(&bytes);
        }
    } else if let Some(hex) = data.strip_prefix(b"HEX:") {
        if hex.len() % 2 != 0 || hex.len() > 131_038 {
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
            let (Some(hi), Some(lo)) = (digit(pair[0]), digit(pair[1])) else {
                return;
            };
            out.push((hi << 4) | lo);
        }
        let _ = clipcore::protocol::TextEnvelope::decode(&out);
    } else {
        let _ = clipcore::protocol::TextEnvelope::decode(data);
    }
});
