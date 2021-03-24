import { randomBytes } from "crypto";
import * as secp256k1 from "../../";

const eq = (v1, v2) =>
  v1.length === v2.length && v1.every((v, i) => v === v2[i]);

function isValidData(data) {
  return (
    secp256k1.isPoint(data.pubkey) &&
    secp256k1.isPoint(data.pubkey_uncompressed) &&
    secp256k1.isPoint(data.pubkey2) &&
    secp256k1.isPointCompressed(data.pubkey) &&
    secp256k1.isPointCompressed(data.pubkey2) &&
    secp256k1.isPrivate(data.seckey) &&
    secp256k1.isPrivate(data.seckey2) &&
    secp256k1.pointAdd(data.pubkey, data.pubkey2) !== null &&
    secp256k1.pointAddScalar(data.pubkey, data.tweak) !== null &&
    secp256k1.pointAddScalar(data.pubkey2, data.tweak) !== null &&
    eq(secp256k1.pointCompress(data.pubkey, false), data.pubkey_uncompressed) &&
    eq(secp256k1.pointFromScalar(data.seckey, true), data.pubkey) &&
    eq(
      secp256k1.pointFromScalar(data.seckey, false),
      data.pubkey_uncompressed
    ) &&
    eq(secp256k1.pointFromScalar(data.seckey2, true), data.pubkey2) &&
    secp256k1.pointMultiply(data.pubkey, data.tweak) !== null &&
    secp256k1.pointMultiply(data.pubkey2, data.tweak) !== null &&
    secp256k1.privateAdd(data.seckey, data.tweak) !== null &&
    secp256k1.privateAdd(data.seckey2, data.tweak) !== null &&
    secp256k1.privateSub(data.seckey, data.tweak) !== null &&
    secp256k1.privateSub(data.seckey2, data.tweak) !== null &&
    secp256k1.verify(
      data.hash,
      data.pubkey,
      secp256k1.sign(data.hash, data.seckey)
    )
  );
}

export function generate() {
  for (;;) {
    const seckey = new Uint8Array(randomBytes(32));
    const seckey2 = new Uint8Array(randomBytes(32));
    const hash = new Uint8Array(randomBytes(32));

    const data = {
      seckey,
      pubkey: secp256k1.pointFromScalar(seckey, true),
      pubkey_uncompressed: secp256k1.pointFromScalar(seckey, false),
      seckey2,
      pubkey2: secp256k1.pointFromScalar(seckey2, true),
      tweak: new Uint8Array(randomBytes(32)),
      hash,
      entropy: new Uint8Array(randomBytes(32)),
      signature: secp256k1.sign(hash, seckey),
    };

    if (isValidData(data)) return data;
  }
}
