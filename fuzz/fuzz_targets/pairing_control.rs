#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((&kind, payload)) = data.split_first() {
        let _ = clipcore::pairing::parse_pair_control(kind, payload);
    }
});
