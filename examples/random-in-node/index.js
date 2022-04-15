import { compare } from "uint8array-tools";
import * as secp256k1 from "../../lib/index.js";
import { randomBytes } from "./random.js";

const eq = (name, a, b) => {
  const equal = compare(a, b) === 0;
  if (!equal) console.log(`${name} not equal`);
  return equal;
};

const assert = (name, bool) => {
  if (!bool) console.log(`${name} not true`);
  return bool;
};

function isValidData(data) {
  return (
    assert("isPoint1", secp256k1.isPoint(data.pubkey)) &&
    assert("isPoint2", secp256k1.isPoint(data.pubkey_uncompressed)) &&
    assert("isPoint3", secp256k1.isPoint(data.pubkey2)) &&
    assert("isPointCompressed1", secp256k1.isPointCompressed(data.pubkey)) &&
    assert("isPointCompressed2", secp256k1.isPointCompressed(data.pubkey2)) &&
    assert("isPrivate1", secp256k1.isPrivate(data.seckey)) &&
    assert("isPrivate2", secp256k1.isPrivate(data.seckey2)) &&
    assert(
      "pointAdd",
      secp256k1.pointAdd(data.pubkey, data.pubkey2) !== null
    ) &&
    assert(
      "pointAddScalar1",
      secp256k1.pointAddScalar(data.pubkey, data.tweak) !== null
    ) &&
    assert(
      "pointAddScalar2",
      secp256k1.pointAddScalar(data.pubkey2, data.tweak) !== null
    ) &&
    eq(
      "pointCompress",
      secp256k1.pointCompress(data.pubkey, false),
      data.pubkey_uncompressed
    ) &&
    eq(
      "pointFromScalar1",
      secp256k1.pointFromScalar(data.seckey, true),
      data.pubkey
    ) &&
    eq(
      "pointFromScalar2",
      secp256k1.pointFromScalar(data.seckey, false),
      data.pubkey_uncompressed
    ) &&
    eq(
      "pointFromScalar3",
      secp256k1.pointFromScalar(data.seckey2, true),
      data.pubkey2
    ) &&
    eq(
      "xOnlyPointFromScalar1",
      secp256k1.xOnlyPointFromScalar(data.seckey),
      data.x_only_pubkey
    ) &&
    eq(
      "xOnlyPointFromScalar2",
      secp256k1.xOnlyPointFromScalar(data.seckey2),
      data.x_only_pubkey2
    ) &&
    eq(
      "xOnlyPointFromPoint1",
      secp256k1.xOnlyPointFromPoint(data.pubkey),
      data.x_only_pubkey
    ) &&
    eq(
      "xOnlyPointFromPoint2",
      secp256k1.xOnlyPointFromPoint(data.pubkey_uncompressed),
      data.x_only_pubkey
    ) &&
    eq(
      "xOnlyPointFromPoint3",
      secp256k1.xOnlyPointFromPoint(data.pubkey2),
      data.x_only_pubkey2
    ) &&
    assert(
      "xOnlyPointAddTweakCheck",
      secp256k1.xOnlyPointAddTweakCheck(
        data.x_only_pubkey,
        data.x_only_pubkey2,
        data.x_only_add_tweak,
        data.x_only_add_parity
      )
    ) &&
    assert(
      "pointMultiply1",
      secp256k1.pointMultiply(data.pubkey, data.tweak) !== null
    ) &&
    assert(
      "pointMultiply2",
      secp256k1.pointMultiply(data.pubkey2, data.tweak) !== null
    ) &&
    assert(
      "privateAdd1",
      secp256k1.privateAdd(data.seckey, data.tweak) !== null
    ) &&
    assert(
      "privateAdd2",
      secp256k1.privateAdd(data.seckey2, data.tweak) !== null
    ) &&
    assert(
      "privateSub1",
      secp256k1.privateSub(data.seckey, data.tweak) !== null
    ) &&
    assert(
      "privateSub2",
      secp256k1.privateSub(data.seckey2, data.tweak) !== null
    ) &&
    assert(
      "verify",
      secp256k1.verify(data.hash, data.pubkey, data.signature)
    ) &&
    assert(
      "verifySchnorr",
      secp256k1.verifySchnorr(
        data.hash,
        data.x_only_pubkey,
        data.schnorr_signature
      )
    )
  );
}

export function generate() {
  let retryCount = 30;
  for (;;) {
    const seckey = randomBytes(32);
    const seckey2 = randomBytes(32);
    const hash = randomBytes(32);
    const tweak = randomBytes(32);
    const entropy = randomBytes(32);

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
    if (retryCount <= 0) throw new Error(`Couldn't generate valid data.`);
    retryCount--;
  }
}
