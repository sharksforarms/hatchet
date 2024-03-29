#![no_main]
use libfuzzer_sys::fuzz_target;

use hatchet::layer::{ip::Ipv4, LayerExt};

fuzz_target!(|data: &[u8]| {
    let _ = Ipv4::parse(data);
});
