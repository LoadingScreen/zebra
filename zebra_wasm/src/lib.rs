use wasm_bindgen::prelude::*;
use zebra_crypto::{SignedMessage};
use std::str::FromStr;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn verify_signature(message: &str) -> bool {
    match SignedMessage::from_str(message) {
        Ok(signed_message) => signed_message.verify(),
        Err(_) => false,
    }
}

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

// Keeping this around for testing purposes
#[wasm_bindgen]
pub fn greet() {
    alert("Hello, wasm-test!");
}

