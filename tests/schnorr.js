import test from "tape";
import { fromHex, toHex } from "./util.js";
import fschnorr from "./fixtures/schnorr.json";

export function parseBip340Vector(f) {
  return {
    ...(f.d ? { d: fromHex(f.d), e: fromHex(f.e) } : {}),
    ...(f.exception ? { exception: f.exception } : { v: f.v }),
    Q: fromHex(f.Q),
    m: fromHex(f.m),
    s: fromHex(f.s),
    comment: f.comment,
  };
}

export default function (secp256k1) {
  const rand = () => Math.floor(Math.random() * 254) + 1; // [1..254];
  const randPubKey = () =>
    secp256k1.xOnlyPointFromScalar(new Uint8Array(32).fill(rand()));

  test("sign schnorr", (t) => {
    for (const fHex of fschnorr.bip340testvectors) {
      if (fHex.d) {
        const f = parseBip340Vector(fHex);
        t.same(
          secp256k1.signSchnorr(f.m, f.d, f.e),
          f.s,
          `signSchnorr(${fHex.m}, ...) == ${fHex.s}`
        );
      }
    }

    t.end();
  });

  test("verify schnorr", (t) => {
    for (const fHex of fschnorr.bip340testvectors) {
      const f = parseBip340Vector(fHex);
      if (f.exception) {
        t.throws(
          () => {
            secp256k1.verifySchnorr(f.m, f.Q, f.s);
          },
          new RegExp(f.exception),
          `${f.comment} throws ${f.exception}`
        );
      } else {
        const resultVerify = secp256k1.verifySchnorr(f.m, f.Q, f.s);
        t.same(resultVerify, f.v, `verifySchnorr(${fHex.m}, ...) == ${fHex.v}`);
      }
    }

    t.end();
  });

  test("scalar to xOnlyPubkey", (t) => {
    for (const fHex of fschnorr.bip340testvectors) {
      if (fHex.d) {
        const f = parseBip340Vector(fHex);
        t.same(
          secp256k1.xOnlyPointFromScalar(f.d),
          f.Q,
          `xOnlyPointFromScalar(${fHex.d}) == ${fHex.Q}`
        );
      }
    }

    t.end();
  });

  test("pubkey to xOnlyPubkey", (t) => {
    for (const fHex of fschnorr.bip340testvectors) {
      if (fHex.d) {
        const f = parseBip340Vector(fHex);
        const pubkey1 = secp256k1.pointFromScalar(f.d, true);
        const pubkey2 = secp256k1.pointFromScalar(f.d, false);
        t.same(
          secp256k1.xOnlyPointFromPoint(pubkey1),
          f.Q,
          `xOnlyPointFromPoint(${toHex(pubkey1)}) == ${fHex.Q}`
        );
        t.same(
          secp256k1.xOnlyPointFromPoint(pubkey2),
          f.Q,
          `xOnlyPointFromPoint(${toHex(pubkey2)}) == ${fHex.Q}`
        );
      }
    }

    t.end();
  });

  test("xonly pubkey tweak add schnorr", (t) => {
    for (let i = 0; i < 50; i++) {
      const pubkey = randPubKey();
      const tweak = randPubKey();
      const { parity, xOnlyPubkey: result } = secp256k1.xOnlyPointAddTweak(
        pubkey,
        tweak
      );
      t.ok(secp256k1.xOnlyPointAddTweakCheck(pubkey, result, tweak, parity));
      t.ok(secp256k1.xOnlyPointAddTweakCheck(pubkey, result, tweak));
      const dummyKey = randPubKey();
      t.notOk(
        secp256k1.xOnlyPointAddTweakCheck(pubkey, dummyKey, tweak, parity)
      );
      t.notOk(secp256k1.xOnlyPointAddTweakCheck(pubkey, dummyKey, tweak));
    }

    t.end();
  });
}
