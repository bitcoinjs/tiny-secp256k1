import {
  ERROR_BAD_PRIVATE,
  ERROR_BAD_POINT,
  ERROR_BAD_TWEAK,
  throwError,
  ERROR_BAD_HASH,
  ERROR_BAD_EXTRA_DATA,
  ERROR_BAD_SIGNATURE,
} from "./wasm_error.js";

export const PRIVATE_KEY_SIZE = 32;
export const PUBLIC_KEY_COMPRESSED_SIZE = 33;
export const PUBLIC_KEY_UNCOMPRESSED_SIZE = 65;
export const TWEAK_SIZE = 32;
export const HASH_SIZE = 32;
export const EXTRA_DATA_SIZE = 32;
export const SIGNATURE_SIZE = 64;

const BN32_ZERO = new Uint8Array(32);
const BN32_N = new Uint8Array([
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  254,
  186,
  174,
  220,
  230,
  175,
  72,
  160,
  59,
  191,
  210,
  94,
  140,
  208,
  54,
  65,
  65,
]);

function isUint8Array(value) {
  return value instanceof Uint8Array;
}

function cmpBN32(data1, data2) {
  for (let i = 0; i < 32; ++i) {
    if (data1[i] !== data2[i]) {
      return data1[i] < data2[i] ? -1 : 1;
    }
  }
  return 0;
}

export function isZero(x) {
  return cmpBN32(x, BN32_ZERO) === 0;
}

export function isPrivate(x) {
  return (
    isUint8Array(x) &&
    x.length === PRIVATE_KEY_SIZE &&
    cmpBN32(x, BN32_ZERO) > 0 &&
    cmpBN32(x, BN32_N) < 0
  );
}

export function isPoint(p) {
  return (
    isUint8Array(p) &&
    (p.length === PUBLIC_KEY_COMPRESSED_SIZE ||
      p.length === PUBLIC_KEY_UNCOMPRESSED_SIZE)
  );
}

export function isPointCompressed(p) {
  return isUint8Array(p) && p.length === PUBLIC_KEY_COMPRESSED_SIZE;
}

function isTweak(tweak) {
  return (
    isUint8Array(tweak) &&
    tweak.length === TWEAK_SIZE &&
    cmpBN32(tweak, BN32_N) < 0
  );
}

function isHash(h) {
  return isUint8Array(h) && h.length === HASH_SIZE;
}

function isExtraData(e) {
  return e === undefined || (isUint8Array(e) && e.length === EXTRA_DATA_SIZE);
}

function isSignature(signature) {
  return (
    isUint8Array(signature) &&
    signature.length === 64 &&
    cmpBN32(signature.subarray(0, 32), BN32_N) < 0 &&
    cmpBN32(signature.subarray(32, 64), BN32_N) < 0
  );
}

export function validatePrivate(d) {
  if (!isPrivate(d)) throwError(ERROR_BAD_PRIVATE);
}

export function validatePoint(p) {
  if (!isPoint(p)) throwError(ERROR_BAD_POINT);
}

export function validateTweak(tweak) {
  if (!isTweak(tweak)) throwError(ERROR_BAD_TWEAK);
}

export function validateHash(h) {
  if (!isHash(h)) throwError(ERROR_BAD_HASH);
}

export function validateExtraData(e) {
  if (!isExtraData(e)) throwError(ERROR_BAD_EXTRA_DATA);
}

export function validateSignature(signature) {
  if (!isSignature(signature)) throwError(ERROR_BAD_SIGNATURE);
}
