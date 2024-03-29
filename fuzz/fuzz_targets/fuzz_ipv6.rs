#![no_main]
use libfuzzer_sys::fuzz_target;

use hatchet::layer::{ip::Ipv6, LayerExt};

fuzz_target!(|data: &[u8]| {
    let _ = Ipv6::parse(data);
});
