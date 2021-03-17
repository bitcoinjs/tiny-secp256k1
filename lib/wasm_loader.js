import { readFileSync } from "fs";
import { URL } from "url";
import * as rand from "./rand.js";
import * as validate_error from "./validate_error.js";

const binary = readFileSync(new URL("secp256k1.wasm", import.meta.url));
const imports = {
  "./rand.js": rand,
  "./validate_error.js": validate_error,
};

const mod = new WebAssembly.Module(binary);
const instance = new WebAssembly.Instance(mod, imports);

export default instance.exports;
