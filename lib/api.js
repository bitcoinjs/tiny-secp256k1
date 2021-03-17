import * as validate from "./validate.js";

export default function createApi(secp256k1) {
  function assumeCompression(compressed, p) {
    return compressed === undefined
      ? p.length
      : compressed === true
      ? validate.PUBLIC_KEY_COMPRESSED_SIZE
      : validate.PUBLIC_KEY_UNCOMPRESSED_SIZE;
  }

  function signWithEntropy(h, d, e) {
    validate.validateHash(h);
    validate.validatePrivate(d);
    validate.validateExtraData(e);
    return secp256k1.signWithEntropy(h, d, e);
  }

  return {
    __initializeContext() {
      secp256k1.initializeContext();
    },

    isPoint(p) {
      return validate.isPoint(p) && secp256k1.isPoint(p);
    },

    isPointCompressed(p) {
      return validate.isPointCompressed(p) && secp256k1.isPoint(p);
    },

    isPrivate(x) {
      return validate.isPrivate(x);
    },

    pointAdd(pA, pB, compressed) {
      validate.validatePoint(pA);
      validate.validatePoint(pB);
      const outputlen = assumeCompression(compressed, pA);
      return secp256k1.pointAdd(pA, pB, outputlen);
    },

    pointAddScalar(p, tweak, compressed) {
      validate.validatePoint(p);
      validate.validateTweak(tweak);
      const outputlen = assumeCompression(compressed, p);
      return secp256k1.pointAddScalar(p, tweak, outputlen);
    },

    pointCompress(p, compressed) {
      validate.validatePoint(p);
      const outputlen = assumeCompression(compressed, p);
      return secp256k1.pointCompress(p, outputlen);
    },

    pointFromScalar(d, compressed = true) {
      validate.validatePrivate(d);
      const outputlen = assumeCompression(compressed);
      return secp256k1.pointFromScalar(d, outputlen);
    },

    pointMultiply(p, tweak, compressed) {
      validate.validatePoint(p);
      validate.validateTweak(tweak);
      const outputlen = assumeCompression(compressed, p);
      return secp256k1.pointMultiply(p, tweak, outputlen);
    },

    privateAdd(d, tweak) {
      validate.validatePrivate(d);
      validate.validateTweak(tweak);
      return secp256k1.privateAdd(d, tweak);
    },

    privateSub(d, tweak) {
      validate.validatePrivate(d);
      validate.validateTweak(tweak);

      // We can not pass zero tweak to WASM, because WASM use `secp256k1_ec_seckey_negate` for tweak negate.
      // (zero is not valid seckey)
      if (validate.isZero(tweak)) {
        return new Uint8Array(d);
      }

      return secp256k1.privateSub(d, tweak);
    },

    sign(h, d) {
      return signWithEntropy(h, d);
    },

    signWithEntropy,

    verify(h, Q, signature, strict = false) {
      validate.validateHash(h);
      validate.validatePoint(Q);
      validate.validateSignature(signature);
      return secp256k1.verify(h, Q, signature, strict === true ? 1 : 0);
    },
  };
}
