#![no_main]
use libfuzzer_sys::fuzz_target;

// Externally supplied control events are parsed as untrusted data. State transitions
// additionally require the opaque Noise-authenticated token, which callers cannot forge.
fuzz_target!(|data: &[u8]| {
    if let Some((&kind, payload)) = data.split_first() {
        if let Ok(control) = clipcore::pairing::parse_pair_control(kind, payload) {
            let _public_binding_fields_are_only_data = control;
        }
    }
});
