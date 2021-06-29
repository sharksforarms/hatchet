#![no_main]
use libfuzzer_sys::fuzz_target;

use hachet::layer::{tcp::Tcp, LayerExt};

fuzz_target!(|data: &[u8]| {
    let _ = Tcp::parse(data);
});
