/*!
    Based on https://github.com/rustwasm/wasm-pack-template
*/
use wasm_bindgen::prelude::*;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use hatchet::packet::Packet;

#[wasm_bindgen]
#[derive(Debug)]
pub struct Packets(Vec<Packet>);

impl Packets {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Packets {
    fn default() -> Self {
        Self(Vec::new())
    }
}

#[wasm_bindgen]
pub fn read_packets(_input: &[u8]) -> Packets {
    Packets::new()
}

