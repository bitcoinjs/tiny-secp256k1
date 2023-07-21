import test from "tape";
import { fromHex, toHex } from "./util.js";
import fecdsa from "./fixtures/ecdsa.json" assert { type: "json" };

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

export default function (secp256k1, type) {
  test(`sign (${type})`, (t) => {
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

      const extraEntropyUndefined = secp256k1.sign(m, d);
      const extraEntropy0 = secp256k1.sign(m, d, buf1);
      const extraEntropy1 = secp256k1.sign(m, d, buf2);
      const extraEntropyRand = secp256k1.sign(m, d, buf3);
      const extraEntropyN = secp256k1.sign(m, d, buf4);
      const extraEntropyMax = secp256k1.sign(m, d, buf5);

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

  test(`signRecoverable (${type})`, (t) => {
    for (const f of fecdsa.valid) {
      const d = fromHex(f.d);
      const m = fromHex(f.m);
      const expected = fromHex(f.signature);

      const res = secp256k1.signRecoverable(m, d);
      t.same(
        res.signature,
        expected,
        `signRecoverable(${f.m}, ...) == { signature: "${f.signature}", ...}`
      );

      t.same(
        res.recoveryId,
        f.recoveryId,
        `signRecoverable(${f.m}, ...) == { recoveryId: "${f.recoveryId}" ....}`
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

      const extraEntropyUndefined = secp256k1.signRecoverable(m, d);
      const extraEntropy0 = secp256k1.signRecoverable(m, d, buf1);
      const extraEntropy1 = secp256k1.signRecoverable(m, d, buf2);
      const extraEntropyRand = secp256k1.signRecoverable(m, d, buf3);
      const extraEntropyN = secp256k1.signRecoverable(m, d, buf4);
      const extraEntropyMax = secp256k1.signRecoverable(m, d, buf5);

      t.same(
        extraEntropyUndefined.signature,
        expectedSig,
        `signRecoverable(${f.m}, ..., undefined) == { signature: "${f.signature}", ...}`
      );
      t.same(
        extraEntropy0.signature,
        expectedExtraEntropy0,
        `signRecoverable(${f.m}, ..., 0) =={ signature: "${f.extraEntropy0}", ...}`
      );
      t.same(
        extraEntropy1.signature,
        expectedExtraEntropy1,
        `signRecoverable(${f.m}, ..., 1) == { signature: "${f.extraEntropy1}", ...}`
      );
      t.same(
        extraEntropyRand.signature,
        expectedExtraEntropyRand,
        `signRecoverable(${f.m}, ..., rand) == { signature: "${f.extraEntropyRand}", ...}`
      );
      t.same(
        extraEntropyN.signature,
        expectedExtraEntropyN,
        `signRecoverable(${f.m}, ..., n) == { signature: "${f.extraEntropyN}", ...}`
      );
      t.same(
        extraEntropyMax.signature,
        expectedExtraEntropyMax,
        `signRecoverable(${f.m}, ..., max256) == { signature: "${f.extraEntropyMax}", ...}`
      );

      t.same(
        extraEntropyUndefined.recoveryId,
        f.recoveryId,
        `signRecoverable(${f.m}, ..., undefined) == { recoveryId: "${f.recoveryId}", ...}`
      );
      t.same(
        extraEntropy0.recoveryId,
        f.recoveryId0,
        `signRecoverable(${f.m}, ..., 0) == { recoveryId: "${f.recoveryId0}", ...}`
      );
      t.same(
        extraEntropy1.recoveryId,
        f.recoveryId1,
        `signRecoverable(${f.m}, ..., 1) == { recoveryId: "${f.recoveryId1}", ...}`
      );
      t.same(
        extraEntropyRand.recoveryId,
        f.recoveryIdRand,
        `signRecoverable(${f.m}, ..., rand) == { recoveryId: "${f.recoveryIdRand}", ...}`
      );
      t.same(
        extraEntropyN.recoveryId,
        f.recoveryIdN,
        `signRecoverable(${f.m}, ..., n) == { recoveryId: "${f.recoveryIdN}", ...}`
      );
      t.same(
        extraEntropyMax.recoveryId,
        f.recoveryIdMax,
        `signRecoverable(${f.m}, ..., max256) == { recoveryId: "${f.recoveryIdMax}", ...}`
      );
    }

    for (const f of fecdsa.invalid.sign) {
      const d = fromHex(f.d);
      const m = fromHex(f.m);

      t.throws(
        () => {
          secp256k1.signRecoverable(m, d);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  test(`verify (${type})`, (t) => {
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

  test(`recover (${type})`, (t) => {
    for (const f of fecdsa.valid) {
      const d = fromHex(f.d);
      const Q = secp256k1.pointFromScalar(d, true);
      const Qu = secp256k1.pointFromScalar(d, false);
      const m = fromHex(f.m);
      const signature = fromHex(f.signature);

      t.same(
        Q,
        secp256k1.recover(m, signature, f.recoveryId, true),
        `recover(${f.m}, ..., true) == ${toHex(Q)}`
      );

      t.same(
        Qu,
        secp256k1.recover(m, signature, f.recoveryId, false),
        `recover(${f.m}, ..., false) == ${toHex(Q)}`
      );
    }

    for (const f of fecdsa.invalid.recover) {
      const m = fromHex(f.m);
      const signature = fromHex(f.signature);

      t.throws(
        () => {
          secp256k1.recover(m, signature, f.recoveryId || 0);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    for (const f of fecdsa.extraEntropy) {
      const d = fromHex(f.d);
      const Q = secp256k1.pointFromScalar(d, true);
      const Qu = secp256k1.pointFromScalar(d, false);
      const m = fromHex(f.m);
      const expectedSig = fromHex(f.signature);
      const expectedExtraEntropy0 = fromHex(f.extraEntropy0);
      const expectedExtraEntropy1 = fromHex(f.extraEntropy1);
      const expectedExtraEntropyRand = fromHex(f.extraEntropyRand);
      const expectedExtraEntropyN = fromHex(f.extraEntropyN);
      const expectedExtraEntropyMax = fromHex(f.extraEntropyMax);

      t.same(
        Q,
        secp256k1.recover(m, expectedSig, f.recoveryId, true),
        `recover(${f.m}, ${f.recoveryId} ..., true) == ${toHex(Q)}`
      );
      t.same(
        Qu,
        secp256k1.recover(m, expectedSig, f.recoveryId, false),
        `recover(${f.m}, ${f.recoveryId} ..., false) == ${toHex(Q)}`
      );

      t.same(
        Q,
        secp256k1.recover(m, expectedExtraEntropy0, f.recoveryId0, true),
        `recover(${f.m}, ${f.recoveryId0} ..., true) == ${toHex(Q)}`
      );
      t.same(
        Qu,
        secp256k1.recover(m, expectedExtraEntropy0, f.recoveryId0, false),
        `recover(${f.m}, ${f.recoveryId0} ..., false) == ${toHex(Q)}`
      );

      t.same(
        Q,
        secp256k1.recover(m, expectedExtraEntropy1, f.recoveryId1, true),
        `recover(${f.m}, ${f.recoveryId1} ..., true) == ${toHex(Q)}`
      );
      t.same(
        Qu,
        secp256k1.recover(m, expectedExtraEntropy1, f.recoveryId1, false),
        `recover(${f.m}, ${f.recoveryId1} ..., false) == ${toHex(Q)}`
      );

      t.same(
        Q,
        secp256k1.recover(m, expectedExtraEntropyRand, f.recoveryIdRand, true),
        `recover(${f.m}, ${f.recoveryIdRand} ..., true) == ${toHex(Q)}`
      );
      t.same(
        Qu,
        secp256k1.recover(m, expectedExtraEntropyRand, f.recoveryIdRand, false),
        `recover(${f.m}, ${f.recoveryIdRand} ..., false) == ${toHex(Q)}`
      );

      t.same(
        Q,
        secp256k1.recover(m, expectedExtraEntropyN, f.recoveryIdN, true),
        `recover(${f.m}, ${f.recoveryIdN} ..., true) == ${toHex(Q)}`
      );
      t.same(
        Qu,
        secp256k1.recover(m, expectedExtraEntropyN, f.recoveryIdN, false),
        `recover(${f.m}, ${f.recoveryIdN} ..., false) == ${toHex(Q)}`
      );

      t.same(
        Q,
        secp256k1.recover(m, expectedExtraEntropyMax, f.recoveryIdMax, true),
        `recover(${f.m}, ${f.recoveryIdMax} ..., true) == ${toHex(Q)}`
      );
      t.same(
        Qu,
        secp256k1.recover(m, expectedExtraEntropyMax, f.recoveryIdMax, false),
        `recover(${f.m}, ${f.recoveryIdMax} ..., false) == ${toHex(Q)}`
      );
    }

    t.end();
  });
}
