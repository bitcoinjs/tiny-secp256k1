import addon from "./addon.js";
import wasm from "./wasm.js";

export const __addon = addon;
export const __wasm = wasm;

export const {
  __initializeContext,
  isPoint,
  isPointCompressed,
  isPrivate,
  pointAdd,
  pointAddScalar,
  pointCompress,
  pointFromScalar,
  pointMultiply,
  privateAdd,
  privateSub,
  sign,
  signWithEntropy,
  verify,
} = addon || wasm;
