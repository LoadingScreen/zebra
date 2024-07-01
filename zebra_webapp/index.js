import * as wasm from "zebra_wasm";

export function verifySignature(messageString) {
    return wasm.verify_signature(messageString);
}
