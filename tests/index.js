const wasm = require("../");

require("./ecdsa")(wasm);
require("./points")(wasm);
require("./privates")(wasm);
