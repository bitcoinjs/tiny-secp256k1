import wasm from "./wasm.js";

export const __addon = null;
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
} = wasm;
