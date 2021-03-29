import createApi from "./api.js";
import * as validate from "./validate.js";
import wasm from "./wasm_loader.js";

const WASM_BUFFER = new Uint8Array(wasm.memory.buffer);
const WASM_PRIVATE_KEY_PTR = wasm.PRIVATE_INPUT.value;
const WASM_PUBLIC_KEY_INPUT_PTR = wasm.PUBLIC_KEY_INPUT.value;
const WASM_PUBLIC_KEY_INPUT_PTR2 = wasm.PUBLIC_KEY_INPUT2.value;
const WASM_TWEAK_INPUT_PTR = wasm.TWEAK_INPUT.value;
const WASM_HASH_INPUT_PTR = wasm.HASH_INPUT.value;
const WASM_EXTRA_DATA_INPUT_PTR = wasm.EXTRA_DATA_INPUT.value;
const WASM_SIGNATURE_INPUT_PTR = wasm.SIGNATURE_INPUT.value;

const PRIVATE_KEY_INPUT = WASM_BUFFER.subarray(
  WASM_PRIVATE_KEY_PTR,
  WASM_PRIVATE_KEY_PTR + validate.PRIVATE_KEY_SIZE
);
const PUBLIC_KEY_INPUT = WASM_BUFFER.subarray(
  WASM_PUBLIC_KEY_INPUT_PTR,
  WASM_PUBLIC_KEY_INPUT_PTR + validate.PUBLIC_KEY_UNCOMPRESSED_SIZE
);
const PUBLIC_KEY_INPUT2 = WASM_BUFFER.subarray(
  WASM_PUBLIC_KEY_INPUT_PTR2,
  WASM_PUBLIC_KEY_INPUT_PTR2 + validate.PUBLIC_KEY_UNCOMPRESSED_SIZE
);
const TWEAK_INPUT = WASM_BUFFER.subarray(
  WASM_TWEAK_INPUT_PTR,
  WASM_TWEAK_INPUT_PTR + validate.TWEAK_SIZE
);
const HASH_INPUT = WASM_BUFFER.subarray(
  WASM_HASH_INPUT_PTR,
  WASM_HASH_INPUT_PTR + validate.HASH_SIZE
);
const EXTRA_DATA_INPUT = WASM_BUFFER.subarray(
  WASM_EXTRA_DATA_INPUT_PTR,
  WASM_EXTRA_DATA_INPUT_PTR + validate.EXTRA_DATA_SIZE
);
const SIGNATURE_INPUT = WASM_BUFFER.subarray(
  WASM_SIGNATURE_INPUT_PTR,
  WASM_SIGNATURE_INPUT_PTR + validate.SIGNATURE_SIZE
);

export default createApi({
  initializeContext() {
    wasm.initializeContext();
  },

  isPoint(p) {
    try {
      PUBLIC_KEY_INPUT.set(p);
      return wasm.isPoint(p.length) === 1;
    } finally {
      PUBLIC_KEY_INPUT.fill(0);
    }
  },

  pointAdd(pA, pB, outputlen) {
    try {
      PUBLIC_KEY_INPUT.set(pA);
      PUBLIC_KEY_INPUT2.set(pB);
      return wasm.pointAdd(pA.length, pB.length, outputlen) === 1
        ? PUBLIC_KEY_INPUT.slice(0, outputlen)
        : null;
    } finally {
      PUBLIC_KEY_INPUT.fill(0);
      PUBLIC_KEY_INPUT2.fill(0);
    }
  },

  pointAddScalar(p, tweak, outputlen) {
    try {
      PUBLIC_KEY_INPUT.set(p);
      TWEAK_INPUT.set(tweak);
      return wasm.pointAddScalar(p.length, outputlen) === 1
        ? PUBLIC_KEY_INPUT.slice(0, outputlen)
        : null;
    } finally {
      PUBLIC_KEY_INPUT.fill(0);
      TWEAK_INPUT.fill(0);
    }
  },

  pointCompress(p, outputlen) {
    try {
      PUBLIC_KEY_INPUT.set(p);
      wasm.pointCompress(p.length, outputlen);
      return PUBLIC_KEY_INPUT.slice(0, outputlen);
    } finally {
      PUBLIC_KEY_INPUT.fill(0);
    }
  },

  pointFromScalar(d, outputlen) {
    try {
      PRIVATE_KEY_INPUT.set(d);
      return wasm.pointFromScalar(outputlen) === 1
        ? PUBLIC_KEY_INPUT.slice(0, outputlen)
        : null;
    } finally {
      PRIVATE_KEY_INPUT.fill(0);
      PUBLIC_KEY_INPUT.fill(0);
    }
  },

  pointMultiply(p, tweak, outputlen) {
    try {
      PUBLIC_KEY_INPUT.set(p);
      TWEAK_INPUT.set(tweak);
      return wasm.pointMultiply(p.length, outputlen) === 1
        ? PUBLIC_KEY_INPUT.slice(0, outputlen)
        : null;
    } finally {
      PUBLIC_KEY_INPUT.fill(0);
      TWEAK_INPUT.fill(0);
    }
  },

  privateAdd(d, tweak) {
    try {
      PRIVATE_KEY_INPUT.set(d);
      TWEAK_INPUT.set(tweak);
      return wasm.privateAdd() === 1
        ? PRIVATE_KEY_INPUT.slice(0, validate.PRIVATE_KEY_SIZE)
        : null;
    } finally {
      PRIVATE_KEY_INPUT.fill(0);
      TWEAK_INPUT.fill(0);
    }
  },

  privateSub(d, tweak) {
    try {
      PRIVATE_KEY_INPUT.set(d);
      TWEAK_INPUT.set(tweak);
      return wasm.privateSub() === 1
        ? PRIVATE_KEY_INPUT.slice(0, validate.PRIVATE_KEY_SIZE)
        : null;
    } finally {
      PRIVATE_KEY_INPUT.fill(0);
      TWEAK_INPUT.fill(0);
    }
  },

  sign(h, d, e) {
    try {
      HASH_INPUT.set(h);
      PRIVATE_KEY_INPUT.set(d);
      if (e !== undefined) EXTRA_DATA_INPUT.set(e);
      wasm.sign(e === undefined ? 0 : 1);
      return SIGNATURE_INPUT.slice(0, validate.SIGNATURE_SIZE);
    } finally {
      HASH_INPUT.fill(0);
      PRIVATE_KEY_INPUT.fill(0);
      if (e !== undefined) EXTRA_DATA_INPUT.fill(0);
      SIGNATURE_INPUT.fill(0);
    }
  },

  verify(h, Q, signature, strict) {
    try {
      HASH_INPUT.set(h);
      PUBLIC_KEY_INPUT.set(Q);
      SIGNATURE_INPUT.set(signature);
      return wasm.verify(Q.length, strict) === 1 ? true : false;
    } finally {
      HASH_INPUT.fill(0);
      PUBLIC_KEY_INPUT.fill(0);
      SIGNATURE_INPUT.fill(0);
    }
  },
});
