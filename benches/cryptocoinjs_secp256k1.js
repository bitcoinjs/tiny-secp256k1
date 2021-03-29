import secp256k1_js from "secp256k1/elliptic.js";
import secp256k1_native from "secp256k1/bindings.js";

export const js = createApi(secp256k1_js);
export const native = createApi(secp256k1_native);

function createApi(secp256k1) {
  return {
    isPoint: (p) => secp256k1.publicKeyVerify(p),
    // isPointCompressed
    isPrivate: (d) => secp256k1.privateKeyVerify(d),
    pointAdd: (pA, pB) => secp256k1.publicKeyCombine([pA, pB]),
    pointAddScalar: (p, tweak) => secp256k1.publicKeyTweakAdd(p, tweak),
    // pointCompress
    pointFromScalar: (d) => secp256k1.publicKeyCreate(d),
    pointMultiply: (p, tweak) => secp256k1.publicKeyTweakMul(p, tweak),
    privateAdd: (d, tweak) =>
      secp256k1.privateKeyTweakAdd(new Uint8Array(d), tweak),
    // privateSub
    sign: (h, d) => secp256k1.ecdsaSign(h, d),
    verify: (h, Q, signature) => secp256k1.ecdsaVerify(signature, h, Q),
  };
}
