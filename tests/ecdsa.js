import { test } from "tape";
import { fromHex, toHex } from "./util.js";
import fecdsa from "./fixtures/ecdsa.json";

const buf1 = fromHex(
  "0000000000000000000000000000000000000000000000000000000000000000"
);
const buf2 = fromHex(
  "0000000000000000000000000000000000000000000000000000000000000001"
);
const buf3 = fromHex(
  "6e723d3fd94ed5d2b6bdd4f123364b0f3ca52af829988a63f8afe91d29db1c33"
);
const buf4 = fromHex(
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
);
const buf5 = fromHex(
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
);

function corrupt(x) {
  function randomUInt8() {
    return Math.floor(Math.random() * 0xff);
  }

  x = Uint8Array.from(x);
  const mask = 1 << randomUInt8() % 8;
  x[randomUInt8() % 32] ^= mask;
  return x;
}

export default function (secp256k1) {
  test("sign", (t) => {
    for (const f of fecdsa.valid) {
      const d = fromHex(f.d);
      const m = fromHex(f.m);
      const expected = fromHex(f.signature);

      t.same(
        secp256k1.sign(m, d),
        expected,
        `sign(${f.m}, ...) == ${f.signature}`
      );
    }

    for (const f of fecdsa.extraEntropy) {
      const d = fromHex(f.d);
      const m = fromHex(f.m);
      const expectedSig = fromHex(f.signature);
      const expectedExtraEntropy0 = fromHex(f.extraEntropy0);
      const expectedExtraEntropy1 = fromHex(f.extraEntropy1);
      const expectedExtraEntropyRand = fromHex(f.extraEntropyRand);
      const expectedExtraEntropyN = fromHex(f.extraEntropyN);
      const expectedExtraEntropyMax = fromHex(f.extraEntropyMax);

      const sig = secp256k1.sign(m, d);

      const extraEntropyUndefined = secp256k1.signWithEntropy(m, d, undefined);
      const extraEntropy0 = secp256k1.signWithEntropy(m, d, buf1);
      const extraEntropy1 = secp256k1.signWithEntropy(m, d, buf2);
      const extraEntropyRand = secp256k1.signWithEntropy(m, d, buf3);
      const extraEntropyN = secp256k1.signWithEntropy(m, d, buf4);
      const extraEntropyMax = secp256k1.signWithEntropy(m, d, buf5);

      t.same(sig, expectedSig, `sign(${f.m}, ...) == ${f.signature}`);
      t.same(
        extraEntropyUndefined,
        expectedSig,
        `sign(${f.m}, ..., undefined) == ${f.signature}`
      );
      t.same(
        extraEntropy0,
        expectedExtraEntropy0,
        `sign(${f.m}, ..., 0) == ${f.signature}`
      );
      t.same(
        extraEntropy1,
        expectedExtraEntropy1,
        `sign(${f.m}, ..., 1) == ${f.signature}`
      );
      t.same(
        extraEntropyRand,
        expectedExtraEntropyRand,
        `sign(${f.m}, ..., rand) == ${f.signature}`
      );
      t.same(
        extraEntropyN,
        expectedExtraEntropyN,
        `sign(${f.m}, ..., n) == ${f.signature}`
      );
      t.same(
        extraEntropyMax,
        expectedExtraEntropyMax,
        `sign(${f.m}, ..., max256) == ${f.signature}`
      );
    }

    for (const f of fecdsa.invalid.sign) {
      const d = fromHex(f.d);
      const m = fromHex(f.m);

      t.throws(
        () => {
          secp256k1.sign(m, d);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  test("verify", (t) => {
    for (const f of fecdsa.valid) {
      const d = fromHex(f.d);
      const Q = secp256k1.pointFromScalar(d, true);
      const Qu = secp256k1.pointFromScalar(d, false);
      const m = fromHex(f.m);
      const signature = fromHex(f.signature);
      const bad = corrupt(signature);

      t.equal(
        secp256k1.verify(m, Q, signature),
        true,
        `verify(${f.signature}) is OK`
      );
      t.equal(
        secp256k1.verify(m, Q, bad),
        false,
        `verify(${toHex(bad)}) is rejected`
      );
      t.equal(
        secp256k1.verify(m, Qu, signature),
        true,
        `verify(${f.signature}) is OK`
      );
      t.equal(
        secp256k1.verify(m, Qu, bad),
        false,
        `verify(${toHex(bad)}) is rejected`
      );
    }

    for (const f of fecdsa.invalid.verify) {
      const Q = fromHex(f.Q);
      const m = fromHex(f.m);
      const signature = fromHex(f.signature);

      if (f.exception) {
        t.throws(
          () => {
            secp256k1.verify(m, Q, signature);
          },
          new RegExp(f.exception),
          `${f.description} throws ${f.exception}`
        );
      } else {
        t.equal(
          secp256k1.verify(m, Q, signature, f.strict),
          false,
          `verify(${f.signature}) is rejected`
        );
        if (f.strict === true) {
          t.equal(
            secp256k1.verify(m, Q, signature, false),
            true,
            `verify(${f.signature}) is OK without strict`
          );
        }
      }
    }

    t.end();
  });
}
