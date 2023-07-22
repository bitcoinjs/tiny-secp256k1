import test from "tape";
import * as secp256k1 from "../lib/index.js";
import * as secp256k1Asm from "../tiny-secp256k1-asmjs/lib/index.js";

import test_ecdsa from "./ecdsa.js";
import test_points from "./points.js";
import test_privates from "./privates.js";
import test_schnorr from "./schnorr.js";

// Closing browser if launched through `browser-run`.
test.onFinish(() => {
  if (process.browser) {
    window.close();
  }
});

test_schnorr(secp256k1, "WASM");
test_ecdsa(secp256k1, "WASM");
test_points(secp256k1, "WASM");
test_privates(secp256k1, "WASM");

// eslint-disable-next-line no-constant-condition
if ("DELETE ME TO RUN" === "") {
  test_schnorr(secp256k1Asm, "ASM.JS");
  test_ecdsa(secp256k1Asm, "ASM.JS");
  test_points(secp256k1Asm, "ASM.JS");
  test_privates(secp256k1Asm, "ASM.JS");
}
