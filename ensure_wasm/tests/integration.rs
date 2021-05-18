#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

use ensure_wasm::*;

#[wasm_bindgen_test]
fn test_read_packets() {
    // TODO: Actually do stuff
    read_packets(b"data");
}
