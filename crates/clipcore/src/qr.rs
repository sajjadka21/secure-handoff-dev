//! Strict bounded canonical CBOR pairing QR v1 codec.
use cbor2::{Value, value::Integer};
use thiserror::Error;

pub const QR_MAX_BYTES: usize = 512;
pub const QR_SCHEMA_VERSION: u64 = 1;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingQr {
    pub issuer_public_key: [u8; 32],
    pub device_id: [u8; 32],
    pub nonce: [u8; 16],
    pub endpoints: Vec<String>,
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum QrError {
    #[error("QR payload exceeds limit or is truncated")]
    Length,
    #[error("QR CBOR structure is invalid, noncanonical, or unsupported")]
    Structure,
    #[error("QR schema fields are invalid")]
    Schema,
    #[error("QR issuer device ID does not match its public key")]
    DeviceIdMismatch,
}

/// Fixed-shape scanner validates attacker-controlled lengths and structure before CBOR allocates.
fn preflight(data: &[u8]) -> Result<(), QrError> {
    if data.is_empty() || data.len() > QR_MAX_BYTES {
        return Err(QrError::Length);
    }
    let mut p = 0;
    let map = byte(data, &mut p)?;
    if map != 0xa6 {
        return Err(QrError::Structure);
    }
    for key in 0..6u8 {
        if byte(data, &mut p)? != key {
            return Err(QrError::Structure);
        }
        match key {
            0 => {
                let (major, n) = head(data, &mut p)?;
                if major != 3 || n != 8 {
                    return Err(QrError::Schema);
                }
                let s = take(data, &mut p, n)?;
                if s != b"CLIPPAIR" {
                    return Err(QrError::Schema);
                }
            }
            1 => {
                let (m, n) = head(data, &mut p)?;
                if m != 0 || n != QR_SCHEMA_VERSION {
                    return Err(QrError::Schema);
                }
            }
            2 | 3 => {
                let (m, n) = head(data, &mut p)?;
                if m != 2 || n != 32 {
                    return Err(QrError::Schema);
                }
                take(data, &mut p, n)?;
            }
            4 => {
                let (m, n) = head(data, &mut p)?;
                if m != 2 || n != 16 {
                    return Err(QrError::Schema);
                }
                take(data, &mut p, n)?;
            }
            5 => {
                let (m, n) = head(data, &mut p)?;
                if m != 4 || n > 4 {
                    return Err(QrError::Schema);
                }
                for _ in 0..n {
                    let (tm, tn) = head(data, &mut p)?;
                    if tm != 3 || tn > 128 {
                        return Err(QrError::Schema);
                    }
                    let s = take(data, &mut p, tn)?;
                    std::str::from_utf8(s).map_err(|_| QrError::Schema)?;
                }
            }
            _ => return Err(QrError::Structure),
        }
    }
    if p != data.len() {
        return Err(QrError::Structure);
    }
    Ok(())
}
fn byte(data: &[u8], p: &mut usize) -> Result<u8, QrError> {
    let b = *data.get(*p).ok_or(QrError::Length)?;
    *p += 1;
    Ok(b)
}
fn take<'a>(data: &'a [u8], p: &mut usize, n: u64) -> Result<&'a [u8], QrError> {
    let n = usize::try_from(n).map_err(|_| QrError::Length)?;
    let end = p.checked_add(n).ok_or(QrError::Length)?;
    let v = data.get(*p..end).ok_or(QrError::Length)?;
    *p = end;
    Ok(v)
}
fn head(data: &[u8], p: &mut usize) -> Result<(u8, u64), QrError> {
    let h = byte(data, p)?;
    let major = h >> 5;
    let ai = h & 31;
    let (n, minimum) = match ai {
        0..=23 => (ai as u64, 0),
        24 => (byte(data, p)? as u64, 24),
        25 => {
            let b = take(data, p, 2)?;
            (u16::from_be_bytes(b.try_into().unwrap()) as u64, 256)
        }
        26 => {
            let b = take(data, p, 4)?;
            (u32::from_be_bytes(b.try_into().unwrap()) as u64, 65_536)
        }
        27 => {
            let b = take(data, p, 8)?;
            (u64::from_be_bytes(b.try_into().unwrap()), 4_294_967_296)
        }
        _ => return Err(QrError::Structure),
    };
    if ai >= 24 && n < minimum {
        return Err(QrError::Structure);
    }
    Ok((major, n))
}

impl PairingQr {
    pub fn schema_version(&self) -> u64 {
        QR_SCHEMA_VERSION
    }
    pub fn encode(&self) -> Result<Vec<u8>, QrError> {
        if self.endpoints.len() > 4 || self.endpoints.iter().any(|s| s.len() > 128) {
            return Err(QrError::Schema);
        }
        if *blake3::hash(&self.issuer_public_key).as_bytes() != self.device_id {
            return Err(QrError::DeviceIdMismatch);
        }
        let map = Value::Map(vec![
            (i(0), Value::Text("CLIPPAIR".into())),
            (i(1), i(QR_SCHEMA_VERSION)),
            (i(2), Value::Bytes(self.issuer_public_key.to_vec())),
            (i(3), Value::Bytes(self.device_id.to_vec())),
            (i(4), Value::Bytes(self.nonce.to_vec())),
            (
                i(5),
                Value::Array(self.endpoints.iter().cloned().map(Value::Text).collect()),
            ),
        ]);
        let bytes = cbor2::to_canonical_vec(&map).map_err(|_| QrError::Structure)?;
        if bytes.len() > QR_MAX_BYTES {
            return Err(QrError::Length);
        }
        Ok(bytes)
    }
    pub fn decode(data: &[u8]) -> Result<Self, QrError> {
        preflight(data)?;
        cbor2::de::validate_slice(data).map_err(|_| QrError::Structure)?;
        let value: Value = cbor2::from_slice(data).map_err(|_| QrError::Structure)?;
        let Value::Map(fields) = value else {
            return Err(QrError::Schema);
        };
        if fields.len() != 6 {
            return Err(QrError::Schema);
        };
        let mut slots: Vec<Option<Value>> = (0..6).map(|_| None).collect();
        for (k, v) in fields {
            let Some(key) = k.as_integer().and_then(|n| u8::try_from(n).ok()) else {
                return Err(QrError::Schema);
            };
            let slot = slots.get_mut(key as usize).ok_or(QrError::Schema)?;
            if slot.replace(v).is_some() {
                return Err(QrError::Schema);
            };
        }
        if slots.iter().any(Option::is_none) {
            return Err(QrError::Schema);
        }
        let vals: Vec<Value> = slots.into_iter().map(Option::unwrap).collect();
        if vals[0].as_text() != Some("CLIPPAIR")
            || vals[1].as_integer().and_then(|n| u64::try_from(n).ok()) != Some(QR_SCHEMA_VERSION)
        {
            return Err(QrError::Schema);
        }
        let key: [u8; 32] = vals[2]
            .as_bytes()
            .ok_or(QrError::Schema)?
            .as_slice()
            .try_into()
            .map_err(|_| QrError::Schema)?;
        let id: [u8; 32] = vals[3]
            .as_bytes()
            .ok_or(QrError::Schema)?
            .as_slice()
            .try_into()
            .map_err(|_| QrError::Schema)?;
        let nonce: [u8; 16] = vals[4]
            .as_bytes()
            .ok_or(QrError::Schema)?
            .as_slice()
            .try_into()
            .map_err(|_| QrError::Schema)?;
        if *blake3::hash(&key).as_bytes() != id {
            return Err(QrError::DeviceIdMismatch);
        }
        let Value::Array(items) = &vals[5] else {
            return Err(QrError::Schema);
        };
        if items.len() > 4 {
            return Err(QrError::Schema);
        }
        let endpoints = items
            .iter()
            .map(|v| {
                let s = v.as_text().ok_or(QrError::Schema)?;
                if s.len() > 128 {
                    return Err(QrError::Schema);
                }
                Ok(s.to_owned())
            })
            .collect::<Result<Vec<_>, QrError>>()?;
        let qr = Self {
            issuer_public_key: key,
            device_id: id,
            nonce,
            endpoints,
        };
        if qr.encode()?.as_slice() != data {
            return Err(QrError::Structure);
        }
        Ok(qr)
    }
}
fn i(n: u64) -> Value {
    Value::Integer(Integer::from(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vector() -> Vec<u8> {
        const H: &str = "a60068434c49505041495201010258202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74035820ea7075b1b6955ed7541ee8d8efbbb9a0b4327e0698c198eeaf837e5a883589f90450000102030405060708090a0b0c0d0e0f0580";
        (0..H.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&H[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn protocol_positive_vector_is_verified_and_roundtrips() {
        let data = vector();
        let qr = PairingQr::decode(&data).unwrap();
        assert_eq!(
            qr.device_id,
            hex32("ea7075b1b6955ed7541ee8d8efbbb9a0b4327e0698c198eeaf837e5a883589f9")
        );
        assert_eq!(qr.encode().unwrap(), data);
    }
    #[test]
    fn rejects_trailing_indefinite_and_nonminimal() {
        let mut a = vector();
        a.push(0);
        assert!(PairingQr::decode(&a).is_err());
        let mut a = vector();
        a[0] = 0xbf;
        assert!(PairingQr::decode(&a).is_err());
        let mut a = vector();
        a[1] = 0x18;
        assert!(PairingQr::decode(&a).is_err());
    }
    #[test]
    fn rejects_duplicate_unknown_and_missing_fields_and_bad_endpoints() {
        let base = vector();
        let mut duplicate = base.clone();
        let at = duplicate.windows(3).position(|w| w == [1, 1, 2]).unwrap() + 2;
        duplicate[at] = 1;
        assert!(PairingQr::decode(&duplicate).is_err());
        let mut unknown = base.clone();
        unknown[at] = 6;
        assert!(PairingQr::decode(&unknown).is_err());
        let mut missing = base.clone();
        missing[0] = 0xa5;
        missing.truncate(missing.len() - 2);
        assert!(PairingQr::decode(&missing).is_err());
        let mut invalid_utf8 = base.clone();
        invalid_utf8.truncate(invalid_utf8.len() - 1);
        invalid_utf8.extend_from_slice(&[0x81, 0x61, 0xff]);
        assert!(PairingQr::decode(&invalid_utf8).is_err());
        let mut too_many = base.clone();
        too_many.truncate(too_many.len() - 1);
        too_many.extend_from_slice(&[0x85]);
        assert!(PairingQr::decode(&too_many).is_err());
        let mut indefinite_array = base;
        *indefinite_array.last_mut().unwrap() = 0x9f;
        indefinite_array.push(0xff);
        assert!(PairingQr::decode(&indefinite_array).is_err());
    }

    #[test]
    fn rejects_oversized_endpoint_before_owned_decode() {
        let mut bytes = vector();
        bytes.truncate(bytes.len() - 1);
        bytes.extend_from_slice(&[0x81, 0x79, 0x00, 0x81]);
        bytes.extend(std::iter::repeat_n(b'a', 129));
        assert!(bytes.len() <= QR_MAX_BYTES);
        assert!(PairingQr::decode(&bytes).is_err());
    }
    #[test]
    fn independently_generated_vector_and_tampered_id() {
        let key = [42; 32];
        let qr = PairingQr {
            issuer_public_key: key,
            device_id: *blake3::hash(&key).as_bytes(),
            nonce: [7; 16],
            endpoints: vec!["127.0.0.1:42".into()],
        };
        let encoded = qr.encode().unwrap();
        assert_eq!(PairingQr::decode(&encoded).unwrap(), qr);
        let mut bad = qr;
        bad.device_id[0] ^= 1;
        assert_eq!(bad.encode(), Err(QrError::DeviceIdMismatch));
    }

    #[test]
    fn checked_in_qr_corpus_seeds_match_their_expected_outcome() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/qr");
        for entry in std::fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let raw = std::fs::read(entry.path()).unwrap();
            let text = raw.strip_prefix(b"HEX:").expect("fixture has HEX prefix");
            let mut bytes = Vec::with_capacity(text.len() / 2);
            let mut digits = text.iter().copied().filter(|b| !b.is_ascii_whitespace());
            while let Some(hi) = digits.next() {
                let lo = digits.next().expect("hex has even length");
                let digit = |v| match v {
                    b'0'..=b'9' => Some(v - b'0'),
                    b'a'..=b'f' => Some(v - b'a' + 10),
                    b'A'..=b'F' => Some(v - b'A' + 10),
                    _ => None,
                };
                bytes.push((digit(hi).unwrap() << 4) | digit(lo).unwrap());
            }
            if name == "valid-spec-vector" || name == "independent-python-vector" {
                assert!(PairingQr::decode(&bytes).is_ok(), "{name}");
            } else {
                assert!(PairingQr::decode(&bytes).is_err(), "{name}");
            }
        }
    }
    proptest::proptest! {#[test]fn arbitrary_bytes_never_panic(data in proptest::collection::vec(proptest::num::u8::ANY,0..600)){let _=PairingQr::decode(&data);}}
    fn hex32(s: &str) -> [u8; 32] {
        let mut o = [0; 32];
        for i in 0..32 {
            o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()
        }
        o
    }
}
