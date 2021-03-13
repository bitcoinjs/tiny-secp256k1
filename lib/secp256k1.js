import { readFileSync } from "fs";
import { URL } from "url";
import * as wasm_error from "./wasm_error.js";
import * as wasm_rand from "./wasm_rand.js";

const binary = readFileSync(new URL("secp256k1.wasm", import.meta.url));
const imports = {
  "./wasm_error.js": wasm_error,
  "./wasm_rand.js": wasm_rand,
};

const mod = new WebAssembly.Module(binary);
const instance = new WebAssembly.Instance(mod, imports);

export default instance.exports;
