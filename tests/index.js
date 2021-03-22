import { test } from "tape";
import * as secp256k1 from "../lib/index.js";

import test_ecdsa from "./ecdsa.js";
import test_points from "./points.js";
import test_privates from "./privates.js";

// Closing browser if launched through `browser-run`.
test.onFinish(() => {
  if (process.browser) {
    window.close();
  }
});

function runTests(secp256k1) {
  if (secp256k1 !== null) {
    test_ecdsa(secp256k1);
    test_points(secp256k1);
    test_privates(secp256k1);
  }
}

runTests(secp256k1.__addon);
runTests(secp256k1.__wasm);

test("functions exported properly", (t) => {
  const fnList = [
    "isPoint",
    "isPointCompressed",
    "isPrivate",
    "pointAdd",
    "pointAddScalar",
    "pointCompress",
    "pointFromScalar",
    "pointMultiply",
    "privateAdd",
    "privateSub",
    "sign",
    "signWithEntropy",
    "verify",
  ];
  const source =
    secp256k1.__initializeContext === secp256k1.__wasm.__initializeContext
      ? secp256k1.__wasm
      : secp256k1.__addon;
  for (const fnName of fnList) {
    t.same(secp256k1[fnName], source[fnName]);
  }

  t.end();
});
