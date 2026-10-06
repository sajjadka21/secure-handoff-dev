"""Small independent RFC 8949 deterministic-CBOR fixture generator (test-only)."""


def head(major: int, value: int) -> bytes:
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value <= 0xFF:
        return bytes([prefix | 24, value])
    raise ValueError("fixture generator only supports one-byte lengths")


def encode(value) -> bytes:
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(map(encode, value))
    if isinstance(value, dict):
        pairs = sorted(value.items(), key=lambda pair: encode(pair[0]))
        return head(5, len(pairs)) + b"".join(encode(k) + encode(v) for k, v in pairs)
    raise TypeError(type(value))


issuer_key = bytes.fromhex(
    "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
)
device_id = bytes.fromhex(
    "ea7075b1b6955ed7541ee8d8efbbb9a0b4327e0698c198eeaf837e5a883589f9"
)
qr = {
    0: "CLIPPAIR",
    1: 1,
    2: issuer_key,
    3: device_id,
    4: bytes(range(16)),
    5: ["lan"],
}
print("HEX:" + encode(qr).hex())
