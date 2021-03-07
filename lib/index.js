const validate = require("./validate");
const wasm = require("./secp256k1");

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

function assumeCompression(compressed, p) {
  return compressed === undefined
    ? p.length
    : compressed === true
    ? validate.PUBLIC_KEY_COMPRESSED_SIZE
    : validate.PUBLIC_KEY_UNCOMPRESSED_SIZE;
}

function __isPoint(p) {
  try {
    PUBLIC_KEY_INPUT.set(p);
    return wasm.isPoint(p.length) === 1;
  } finally {
    PUBLIC_KEY_INPUT.fill(0);
  }
}

function isPoint(p) {
  return validate.isPoint(p) && __isPoint(p);
}

function isPointCompressed(p) {
  return validate.isPointCompressed(p) && __isPoint(p);
}

function isPrivate(x) {
  return validate.isPrivate(x);
}

function pointAdd(pA, pB, compressed) {
  validate.validatePoint(pA);
  validate.validatePoint(pB);
  const outputlen = assumeCompression(compressed, pA);

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
}

function pointAddScalar(p, tweak, compressed) {
  validate.validatePoint(p);
  validate.validateTweak(tweak);
  let outputlen = assumeCompression(compressed, p);

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
}

function pointCompress(p, compressed) {
  validate.validatePoint(p);
  const outputlen = assumeCompression(compressed, p);

  try {
    PUBLIC_KEY_INPUT.set(p);
    wasm.pointCompress(p.length, outputlen);
    return PUBLIC_KEY_INPUT.slice(0, outputlen);
  } finally {
    PUBLIC_KEY_INPUT.fill(0);
  }
}

function pointFromScalar(d, compressed = true) {
  validate.validatePrivate(d);
  const outputlen = assumeCompression(compressed);

  try {
    PRIVATE_KEY_INPUT.set(d);
    return wasm.pointFromScalar(outputlen) === 1
      ? PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    PRIVATE_KEY_INPUT.fill(0);
    PUBLIC_KEY_INPUT.fill(0);
  }
}

function pointMultiply(p, tweak, compressed) {
  validate.validatePoint(p);
  validate.validateTweak(tweak);
  let outputlen = assumeCompression(compressed, p);

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
}

function privateAdd(d, tweak) {
  validate.validatePrivate(d);
  validate.validateTweak(tweak);

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
}

function privateSub(d, tweak) {
  validate.validatePrivate(d);
  validate.validateTweak(tweak);

  // We can not pass zero tweak to WASM, because use `secp256k1_ec_seckey_negate` for tweak negate.
  // (because zero is not valid seckey)
  if (validate.isZero(tweak)) {
    return new Uint8Array(d);
  }

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
}

function sign(h, d) {
  return signWithEntropy(h, d);
}

function signWithEntropy(h, d, e) {
  validate.validateHash(h);
  validate.validatePrivate(d);
  validate.validateExtraData(e);

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
}

function verify(h, Q, signature, strict = false) {
  validate.validateHash(h);
  validate.validatePoint(Q);
  validate.validateSignature(signature);

  try {
    HASH_INPUT.set(h);
    PUBLIC_KEY_INPUT.set(Q);
    SIGNATURE_INPUT.set(signature);
    return wasm.verify(Q.length, strict === true ? 1 : 0) === 1 ? true : false;
  } finally {
    HASH_INPUT.fill(0);
    PUBLIC_KEY_INPUT.fill(0);
    SIGNATURE_INPUT.fill(0);
  }
}

module.exports = {
  __initializeContext: wasm.initializeContext,
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
};
