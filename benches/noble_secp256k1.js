import * as secp256k1 from "noble-secp256k1";

export default {
  // isPoint
  // isPointCompressed
  // isPrivate
  // pointAdd
  // pointAddScalar
  // pointCompress
  pointFromScalar: secp256k1.getPublicKey,
  // pointMultiply
  // privateAdd
  // privateSub
  sign: secp256k1.sign,
  // signWithEntropy
  // verify: (h, Q, signature) => secp256k1.verify(signature, h, Q),
};
