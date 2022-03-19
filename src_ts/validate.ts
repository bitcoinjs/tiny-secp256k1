import {
  ERROR_BAD_PRIVATE,
  ERROR_BAD_POINT,
  ERROR_BAD_TWEAK,
  throwError,
  ERROR_BAD_HASH,
  ERROR_BAD_EXTRA_DATA,
  ERROR_BAD_SIGNATURE,
  ERROR_BAD_PARITY,
  ERROR_BAD_RECOVERY_ID,
} from "./validate_error.js";

export const PRIVATE_KEY_SIZE = 32;
export const PUBLIC_KEY_COMPRESSED_SIZE = 33;
export const PUBLIC_KEY_UNCOMPRESSED_SIZE = 65;
export const X_ONLY_PUBLIC_KEY_SIZE = 32;
export const TWEAK_SIZE = 32;
export const HASH_SIZE = 32;
export const EXTRA_DATA_SIZE = 32;
export const SIGNATURE_SIZE = 64;

const BN32_ZERO = new Uint8Array(32);
const BN32_N = new Uint8Array([
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  254, 186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
]);

// Difference between field and order
const BN32_P_MINUS_N = new Uint8Array([
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 69, 81, 35, 25, 80, 183, 95,
  196, 64, 45, 161, 114, 47, 201, 186, 238,
]);

function isUint8Array(value: Uint8Array): boolean {
  return value instanceof Uint8Array;
}

function cmpBN32(data1: Uint8Array, data2: Uint8Array): number {
  for (let i = 0; i < 32; ++i) {
    if (data1[i] !== data2[i]) {
      return data1[i] < data2[i] ? -1 : 1;
    }
  }
  return 0;
}

export function isZero(x: Uint8Array): boolean {
  return cmpBN32(x, BN32_ZERO) === 0;
}

export function isPrivate(x: Uint8Array): boolean {
  return (
    isUint8Array(x) &&
    x.length === PRIVATE_KEY_SIZE &&
    cmpBN32(x, BN32_ZERO) > 0 &&
    cmpBN32(x, BN32_N) < 0
  );
}

export function isPoint(p: Uint8Array): boolean {
  return (
    isUint8Array(p) &&
    (p.length === PUBLIC_KEY_COMPRESSED_SIZE ||
      p.length === PUBLIC_KEY_UNCOMPRESSED_SIZE ||
      p.length === X_ONLY_PUBLIC_KEY_SIZE)
  );
}

export function isXOnlyPoint(p: Uint8Array): boolean {
  return isUint8Array(p) && p.length === X_ONLY_PUBLIC_KEY_SIZE;
}

export function isDERPoint(p: Uint8Array): boolean {
  return (
    isUint8Array(p) &&
    (p.length === PUBLIC_KEY_COMPRESSED_SIZE ||
      p.length === PUBLIC_KEY_UNCOMPRESSED_SIZE)
  );
}

export function isPointCompressed(p: Uint8Array): boolean {
  return isUint8Array(p) && p.length === PUBLIC_KEY_COMPRESSED_SIZE;
}

function isTweak(tweak: Uint8Array): boolean {
  return (
    isUint8Array(tweak) &&
    tweak.length === TWEAK_SIZE &&
    cmpBN32(tweak, BN32_N) < 0
  );
}

function isHash(h: Uint8Array): boolean {
  return isUint8Array(h) && h.length === HASH_SIZE;
}

function isExtraData(e?: Uint8Array): boolean {
  return e === undefined || (isUint8Array(e) && e.length === EXTRA_DATA_SIZE);
}

function isSignature(signature: Uint8Array): boolean {
  return (
    isUint8Array(signature) &&
    signature.length === 64 &&
    cmpBN32(signature.subarray(0, 32), BN32_N) < 0 &&
    cmpBN32(signature.subarray(32, 64), BN32_N) < 0
  );
}

function isSigrLessThanPMinusN(signature: Uint8Array): boolean {
  return (
    isUint8Array(signature) &&
    signature.length === 64 &&
    cmpBN32(signature.subarray(0, 32), BN32_P_MINUS_N) < 0
  );
}

export function validateParity(p: 1 | 0): void {
  if (p !== 0 && p !== 1) throwError(ERROR_BAD_PARITY);
}

export function validatePrivate(d: Uint8Array): void {
  if (!isPrivate(d)) throwError(ERROR_BAD_PRIVATE);
}

export function validatePoint(p: Uint8Array): void {
  if (!isPoint(p)) throwError(ERROR_BAD_POINT);
}

export function validateXOnlyPoint(p: Uint8Array): void {
  if (!isXOnlyPoint(p)) throwError(ERROR_BAD_POINT);
}

export function validateTweak(tweak: Uint8Array): void {
  if (!isTweak(tweak)) throwError(ERROR_BAD_TWEAK);
}

export function validateHash(h: Uint8Array): void {
  if (!isHash(h)) throwError(ERROR_BAD_HASH);
}

export function validateExtraData(e?: Uint8Array): void {
  if (!isExtraData(e)) throwError(ERROR_BAD_EXTRA_DATA);
}

export function validateSignature(signature: Uint8Array): void {
  if (!isSignature(signature)) throwError(ERROR_BAD_SIGNATURE);
}

export function validateSignatureCustom(validatorFn: () => boolean): void {
  if (!validatorFn()) throwError(ERROR_BAD_SIGNATURE);
}

export function validateSignatureNonzeroRS(signature: Uint8Array): void {
  if (isZero(signature.subarray(0, 32))) throwError(ERROR_BAD_SIGNATURE);
  if (isZero(signature.subarray(32, 64))) throwError(ERROR_BAD_SIGNATURE);
}

export function validateSigrPMinusN(signature: Uint8Array): void {
  if (!isSigrLessThanPMinusN(signature)) throwError(ERROR_BAD_RECOVERY_ID);
}
