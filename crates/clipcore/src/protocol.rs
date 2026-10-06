use crate::{CURRENT_PROTOCOL_VERSION, MAX_TEXT_BYTES};
use anyhow::{Result, bail, ensure};

pub const ENVELOPE_MAGIC: &[u8; 4] = b"CLIP";
pub const KIND_TEXT: u8 = 1;
const HEADER_LEN: usize = 4 + 2 + 1 + 8 + 16 + 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextEnvelope {
    pub sequence: u64,
    pub message_id: [u8; 16],
    pub text: Vec<u8>,
}

impl TextEnvelope {
    pub fn new(sequence: u64, message_id: [u8; 16], text: Vec<u8>) -> Result<Self> {
        ensure!(text.len() <= MAX_TEXT_BYTES, "text payload exceeds limit");
        Ok(Self {
            sequence,
            message_id,
            text,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.text.len() <= MAX_TEXT_BYTES,
            "text payload exceeds limit"
        );
        let mut out = Vec::with_capacity(HEADER_LEN + self.text.len());
        out.extend_from_slice(ENVELOPE_MAGIC);
        out.extend_from_slice(&CURRENT_PROTOCOL_VERSION.to_be_bytes());
        out.push(KIND_TEXT);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.message_id);
        out.extend_from_slice(&(self.text.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.text);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        ensure!(input.len() >= HEADER_LEN, "truncated envelope");
        ensure!(&input[..4] == ENVELOPE_MAGIC, "invalid envelope magic");
        let version = u16::from_be_bytes([input[4], input[5]]);
        ensure!(
            version == CURRENT_PROTOCOL_VERSION,
            "unsupported protocol version {version}"
        );
        ensure!(input[6] == KIND_TEXT, "unsupported message kind");
        let sequence = u64::from_be_bytes(input[7..15].try_into()?);
        let message_id = input[15..31].try_into()?;
        let len = u32::from_be_bytes(input[31..35].try_into()?) as usize;
        ensure!(len <= MAX_TEXT_BYTES, "text payload exceeds limit");
        ensure!(input.len() == HEADER_LEN + len, "envelope length mismatch");
        let text = input[HEADER_LEN..].to_vec();
        if std::str::from_utf8(&text).is_err() {
            bail!("text payload is not UTF-8");
        }
        Ok(Self {
            sequence,
            message_id,
            text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_envelope_round_trip_and_rejects_version_downgrade() {
        let e = TextEnvelope::new(0, [7; 16], b"hello".to_vec()).unwrap();
        let encoded = e.encode().unwrap();
        assert_eq!(TextEnvelope::decode(&encoded).unwrap(), e);
        let mut old = encoded;
        old[5] = 0;
        assert!(TextEnvelope::decode(&old).is_err());
    }
}
