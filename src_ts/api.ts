import * as validate from "./validate.js";

export interface Secp256k1InternalApi {
  initializeContext: () => void;
  isPoint: (p: Uint8Array) => boolean;
  pointAdd: (
    pA: Uint8Array,
    pB: Uint8Array,
    outputlen: number
  ) => Uint8Array | null;
  pointAddScalar: (
    p: Uint8Array,
    tweak: Uint8Array,
    outputlen: number
  ) => Uint8Array | null;
  pointCompress: (p: Uint8Array, outputlen: number) => Uint8Array;
  pointFromScalar: (d: Uint8Array, outputlen: number) => Uint8Array | null;
  pointMultiply: (
    p: Uint8Array,
    tweak: Uint8Array,
    outputlen: number
  ) => Uint8Array | null;
  privateAdd: (d: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
  privateSub: (d: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
  sign: (h: Uint8Array, d: Uint8Array, e?: Uint8Array) => Uint8Array;
  verify: (
    h: Uint8Array,
    Q: Uint8Array,
    signature: Uint8Array,
    strict: number
  ) => boolean;
}

export interface Secp256k1Api {
  __initializeContext: () => void;
  isPoint: (p: Uint8Array) => boolean;
  isPointCompressed: (p: Uint8Array) => boolean;
  isPrivate: (d: Uint8Array) => boolean;
  pointAdd: (
    pA: Uint8Array,
    pB: Uint8Array,
    compressed?: boolean
  ) => Uint8Array | null;
  pointAddScalar: (
    p: Uint8Array,
    tweak: Uint8Array,
    compressed?: boolean
  ) => Uint8Array | null;
  pointCompress: (p: Uint8Array, compressed?: boolean) => Uint8Array;
  pointFromScalar: (d: Uint8Array, compressed?: boolean) => Uint8Array | null;
  pointMultiply: (
    p: Uint8Array,
    tweak: Uint8Array,
    compressed?: boolean
  ) => Uint8Array | null;
  privateAdd: (d: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
  privateSub: (d: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
  sign: (h: Uint8Array, d: Uint8Array, e?: Uint8Array) => Uint8Array;
  verify: (
    h: Uint8Array,
    Q: Uint8Array,
    signature: Uint8Array,
    strict: boolean
  ) => boolean;
}

export default function createApi(
  secp256k1: Secp256k1InternalApi
): Secp256k1Api {
  function assumeCompression(compressed?: boolean, p?: Uint8Array): number {
    if (compressed === undefined) {
      return p !== undefined ? p.length : validate.PUBLIC_KEY_COMPRESSED_SIZE;
    }
    return compressed
      ? validate.PUBLIC_KEY_COMPRESSED_SIZE
      : validate.PUBLIC_KEY_UNCOMPRESSED_SIZE;
  }

  return {
    __initializeContext(): void {
      secp256k1.initializeContext();
    },

    isPoint(p: Uint8Array): boolean {
      return validate.isPoint(p) && secp256k1.isPoint(p);
    },

    isPointCompressed(p: Uint8Array): boolean {
      return validate.isPointCompressed(p) && secp256k1.isPoint(p);
    },

    isPrivate(d: Uint8Array): boolean {
      return validate.isPrivate(d);
    },

    pointAdd(
      pA: Uint8Array,
      pB: Uint8Array,
      compressed?: boolean
    ): Uint8Array | null {
      validate.validatePoint(pA);
      validate.validatePoint(pB);
      const outputlen = assumeCompression(compressed, pA);
      return secp256k1.pointAdd(pA, pB, outputlen);
    },

    pointAddScalar(
      p: Uint8Array,
      tweak: Uint8Array,
      compressed?: boolean
    ): Uint8Array | null {
      validate.validatePoint(p);
      validate.validateTweak(tweak);
      const outputlen = assumeCompression(compressed, p);
      return secp256k1.pointAddScalar(p, tweak, outputlen);
    },

    pointCompress(p: Uint8Array, compressed?: boolean): Uint8Array {
      validate.validatePoint(p);
      const outputlen = assumeCompression(compressed, p);
      return secp256k1.pointCompress(p, outputlen);
    },

    pointFromScalar(d: Uint8Array, compressed?: boolean): Uint8Array | null {
      validate.validatePrivate(d);
      const outputlen = assumeCompression(compressed);
      return secp256k1.pointFromScalar(d, outputlen);
    },

    pointMultiply(
      p: Uint8Array,
      tweak: Uint8Array,
      compressed?: boolean
    ): Uint8Array | null {
      validate.validatePoint(p);
      validate.validateTweak(tweak);
      const outputlen = assumeCompression(compressed, p);
      return secp256k1.pointMultiply(p, tweak, outputlen);
    },

    privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null {
      validate.validatePrivate(d);
      validate.validateTweak(tweak);
      return secp256k1.privateAdd(d, tweak);
    },

    privateSub(d: Uint8Array, tweak: Uint8Array): Uint8Array | null {
      validate.validatePrivate(d);
      validate.validateTweak(tweak);

      // We can not pass zero tweak to WASM, because WASM use `secp256k1_ec_seckey_negate` for tweak negate.
      // (zero is not valid seckey)
      if (validate.isZero(tweak)) {
        return new Uint8Array(d);
      }

      return secp256k1.privateSub(d, tweak);
    },

    sign(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array {
      validate.validateHash(h);
      validate.validatePrivate(d);
      validate.validateExtraData(e);
      return secp256k1.sign(h, d, e);
    },

    verify(
      h: Uint8Array,
      Q: Uint8Array,
      signature: Uint8Array,
      strict = false
    ): boolean {
      validate.validateHash(h);
      validate.validatePoint(Q);
      validate.validateSignature(signature);
      return secp256k1.verify(h, Q, signature, strict === true ? 1 : 0);
    },
  };
}
