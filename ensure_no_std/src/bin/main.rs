//! Based on https://github.com/rustwasm/wee_alloc/tree/master/example
//! Run with `cargo +nightly run --release`

#![no_std]
#![no_main]
#![feature(core_intrinsics, lang_items, alloc_error_handler)]

extern crate alloc;
extern crate wee_alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// Need to provide a tiny `panic` implementation for `#![no_std]`.
// This translates into an `unreachable` instruction that will
// raise a `trap` the WebAssembly execution if we panic at runtime.
#[panic_handler]
#[no_mangle]
unsafe fn panic(_info: &::core::panic::PanicInfo) -> ! {
    ::core::intrinsics::abort();
}

// Need to provide an allocation error handler which just aborts
// the execution with trap.
#[alloc_error_handler]
#[no_mangle]
unsafe fn oom(_: ::core::alloc::Layout) -> ! {
    ::core::intrinsics::abort();
}

// Needed for non-wasm targets.
#[lang = "eh_personality"]
#[no_mangle]
extern "C" fn eh_personality() {}

use alloc::vec::Vec;
use hachet::packet::Packet;

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

pub fn read_packets(_input: &[u8]) -> Packets {
    Packets::new()
}

#[no_mangle]
pub extern "C" fn main() -> i32 {
    read_packets(b"test");

    0
}
