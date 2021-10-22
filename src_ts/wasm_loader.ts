import { readFileSync } from "fs";
import { URL } from "url";
import * as rand from "./rand.js";
import * as validate_error from "./validate_error.js";

const { pathname } = new URL("secp256k1.wasm", import.meta.url);

const binary = readFileSync(pathname);
const imports = {
  "./rand.js": rand,
  "./validate_error.js": validate_error,
};

const mod = new WebAssembly.Module(binary);
const instance = new WebAssembly.Instance(mod, imports);

interface WebAssemblyMemory {
  buffer: Uint8Array;
}

interface WebAssemblyGlobal {
  value: number;
}

interface Secp256k1WASM {
  memory: WebAssemblyMemory;

  PRIVATE_INPUT: WebAssemblyGlobal;
  PUBLIC_KEY_INPUT: WebAssemblyGlobal;
  PUBLIC_KEY_INPUT2: WebAssemblyGlobal;
  X_ONLY_PUBLIC_KEY_INPUT: WebAssemblyGlobal;
  TWEAK_INPUT: WebAssemblyGlobal;
  HASH_INPUT: WebAssemblyGlobal;
  EXTRA_DATA_INPUT: WebAssemblyGlobal;
  SIGNATURE_INPUT: WebAssemblyGlobal;

  initializeContext: () => void;
  isPoint: (p: number) => number;
  pointAdd: (pA: number, pB: number, outputlen: number) => number;
  pointAddScalar: (p: number, outputlen: number) => number;
  pointCompress: (p: number, outputlen: number) => number;
  pointFromScalar: (outputlen: number) => number;
  pointMultiply: (p: number, outputlen: number) => number;
  privateAdd: () => number;
  privateSub: () => number;
  sign: (e: number) => void;
  signSchnorr: (e: number) => void;
  verify: (Q: number, strict: number) => number;
  verifySchnorr: () => number;
}

export default instance.exports as unknown as Secp256k1WASM;
