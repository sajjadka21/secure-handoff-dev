# Fuzz targets

This standalone cargo-fuzz workspace contains bounded targets for the QR codec, text envelope, pairing control parser, and externally supplied pairing-event bytes. The event target currently validates the fixed control parser; it does not synthesize authenticated controls or claim full state-machine fuzz coverage.

QR and envelope seeds use a small `HEX:` ASCII wrapper decoded by their target so the checked-in positive/negative fixtures remain reviewable. `MAX_VALID_ENVELOPE` causes the envelope target to synthesize and decode the maximum-size valid text envelope. Pairing-control seeds are raw bytes: the first byte selects control kind and the remaining bytes are the fixed control payload.

Run with a nightly Rust toolchain and cargo-fuzz 0.13.2, for example:

```sh
cargo fuzz run qr -- -max_total_time=20
cargo fuzz run envelope -- -max_total_time=20
cargo fuzz run pairing_control -- -max_total_time=20
cargo fuzz run pairing_events -- -max_total_time=20
```

Fuzzing is input robustness evidence only; it is not a security audit or proof of cryptographic correctness.
