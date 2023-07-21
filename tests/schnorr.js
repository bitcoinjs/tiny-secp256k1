import test from "tape";
import { fromHex, toHex } from "./util.js";
import fschnorr from "./fixtures/schnorr.json" assert { type: "json" };

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

export function parseTweakAddVector(f) {
  return {
    pubkey: fromHex(f.pubkey),
    tweak: fromHex(f.tweak),
    parity: f.parity,
    result: f.result ? fromHex(f.result) : f.result,
  };
}

export default function (secp256k1, type) {
  const rand = () => Math.floor(Math.random() * 254) + 1; // [1..254];
  const randPubKey = () =>
    secp256k1.xOnlyPointFromScalar(new Uint8Array(32).fill(rand()));

  test(`sign schnorr (${type})`, (t) => {
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

  test(`verify schnorr (${type})`, (t) => {
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

  test(`scalar to xOnlyPubkey (${type})`, (t) => {
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

  test(`pubkey to xOnlyPubkey (${type})`, (t) => {
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

  test(`xonly pubkey tweak add schnorr (${type})`, (t) => {
    for (const fHex of fschnorr.tweakaddvectors) {
      const f = parseTweakAddVector(fHex);
      const res = secp256k1.xOnlyPointAddTweak(f.pubkey, f.tweak);
      if (f.result === null) {
        t.same(
          res,
          f.result,
          `xOnlyPointAddTweak returns null when G pubkey and n - 1 tweak used`
        );
        continue;
      }
      const { parity, xOnlyPubkey: result } = res;
      t.same(
        result,
        f.result,
        `xOnlyPointAddTweak(${fHex.pubkey},${fHex.tweak}) == ${fHex.result} result`
      );
      t.same(
        parity,
        f.parity,
        `xOnlyPointAddTweak(${fHex.pubkey},${fHex.tweak}) == ${fHex.parity} parity`
      );
      // test check method
      t.ok(
        secp256k1.xOnlyPointAddTweakCheck(
          f.pubkey,
          f.tweak,
          f.result,
          f.parity
        ),
        `xOnlyPointAddTweakCheck(${fHex.pubkey},${fHex.tweak},${fHex.result},${fHex.parity}) == true`
      );
      t.ok(
        secp256k1.xOnlyPointAddTweakCheck(f.pubkey, f.tweak, f.result),
        `xOnlyPointAddTweakCheck(${fHex.pubkey},${fHex.tweak},${fHex.result}) == true`
      );
      const dummyKey = randPubKey();
      t.notOk(
        secp256k1.xOnlyPointAddTweakCheck(
          f.pubkey,
          f.tweak,
          dummyKey,
          f.parity
        ),
        `xOnlyPointAddTweakCheck(${fHex.pubkey},${fHex.tweak},${toHex(
          dummyKey
        )},${fHex.parity}) == false`
      );
      t.notOk(
        secp256k1.xOnlyPointAddTweakCheck(f.pubkey, f.tweak, dummyKey),
        `xOnlyPointAddTweakCheck(${fHex.pubkey},${fHex.tweak},${toHex(
          dummyKey
        )}) == false`
      );
    }

    t.end();
  });
}
