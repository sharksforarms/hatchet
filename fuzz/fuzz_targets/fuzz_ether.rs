#![no_main]
use libfuzzer_sys::fuzz_target;

use hatchet::layer::{ether::Ether, LayerExt};

fuzz_target!(|data: &[u8]| {
    let _ = Ether::parse(data);
});
