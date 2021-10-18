import { randomBytes } from "crypto";
import { compare } from "uint8array-tools";
import * as secp256k1 from "../../lib/index.js";

const eq = (a, b) => compare(a, b) === 0;

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
    eq(secp256k1.xOnlyPointFromScalar(data.seckey), data.x_only_pubkey) &&
    eq(secp256k1.xOnlyPointFromScalar(data.seckey2), data.x_only_pubkey2) &&
    eq(secp256k1.xOnlyPointFromPoint(data.pubkey), data.x_only_pubkey) &&
    eq(
      secp256k1.xOnlyPointFromPoint(data.pubkey_uncompressed),
      data.x_only_pubkey
    ) &&
    eq(secp256k1.xOnlyPointFromPoint(data.pubkey2), data.x_only_pubkey2) &&
    secp256k1.xOnlyPointAddTweakCheck(
      data.x_only_pubkey,
      data.x_only_add_tweak,
      data.x_only_pubkey2,
      data.x_only_add_parity
    ) &&
    secp256k1.pointMultiply(data.pubkey, data.tweak) !== null &&
    secp256k1.pointMultiply(data.pubkey2, data.tweak) !== null &&
    secp256k1.privateAdd(data.seckey, data.tweak) !== null &&
    secp256k1.privateAdd(data.seckey2, data.tweak) !== null &&
    secp256k1.privateSub(data.seckey, data.tweak) !== null &&
    secp256k1.privateSub(data.seckey2, data.tweak) !== null &&
    secp256k1.verify(data.hash, data.pubkey, data.signature) &&
    secp256k1.verifySchnorr(
      data.hash,
      data.x_only_pubkey,
      data.schnorr_signature
    )
  );
}

export function generate() {
  for (;;) {
    const seckey = new Uint8Array(randomBytes(32));
    const seckey2 = new Uint8Array(randomBytes(32));
    const hash = new Uint8Array(randomBytes(32));
    const tweak = new Uint8Array(randomBytes(32));
    const entropy = new Uint8Array(randomBytes(32));

    const x_only_pubkey = secp256k1.xOnlyPointFromScalar(seckey);
    const x_only_pubkey2 = secp256k1.xOnlyPointFromScalar(seckey2);
    const { parity: x_only_add_parity, xOnlyPubkey: x_only_add_tweak } =
      secp256k1.xOnlyPointAddTweak(x_only_pubkey, x_only_pubkey2);

    const data = {
      seckey,
      pubkey: secp256k1.pointFromScalar(seckey, true),
      pubkey_uncompressed: secp256k1.pointFromScalar(seckey, false),
      x_only_pubkey,
      seckey2,
      pubkey2: secp256k1.pointFromScalar(seckey2, true),
      x_only_pubkey2,
      x_only_add_tweak,
      x_only_add_parity,
      tweak,
      hash,
      entropy,
      signature: secp256k1.sign(hash, seckey),
      schnorr_signature: secp256k1.signSchnorr(hash, seckey),
    };

    if (isValidData(data)) return data;
  }
}
