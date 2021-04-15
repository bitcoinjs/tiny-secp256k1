import test from "tape";
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

test_ecdsa(secp256k1);
test_points(secp256k1);
test_privates(secp256k1);
