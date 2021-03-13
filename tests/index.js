import { test } from "tape";
import * as wasm from "../lib/index.js";

import test_ecdsa from "./ecdsa.js";
import test_points from "./points.js";
import test_privates from "./privates.js";

test_ecdsa(wasm);
test_points(wasm);
test_privates(wasm);

// Closing browser if launched through `browser-run`.
test.onFinish(() => {
  try {
    window.close();
  } catch (_err) {}
});
