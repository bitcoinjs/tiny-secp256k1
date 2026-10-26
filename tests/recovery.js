import test from "tape";
import { fromHex } from "./util.js";
import fecdsa from "./fixtures/ecdsa.json" assert { type: "json" };

export default function (secp256k1, backend, type) {
  const f = fecdsa.valid[0];
  const hash = fromHex(f.m);
  const signature = fromHex(f.signature);
  const privateKey = fromHex(f.d);

  test(`recover rejects invalid recovery IDs (${type})`, (t) => {
    const expected = secp256k1.pointFromScalar(privateKey, true);
    for (const recoveryId of [
      -1,
      4,
      0.5,
      1.5,
      NaN,
      Infinity,
      -Infinity,
      0x100000000,
      "0",
      null,
      undefined,
    ]) {
      t.throws(
        () => secp256k1.recover(hash, signature, recoveryId, true),
        (error) =>
          error instanceof TypeError && error.message === "Bad Recovery Id",
        `rejects ${String(recoveryId)} with a validation error`
      );
      t.same(
        secp256k1.recover(hash, signature, f.recoveryId, true),
        expected,
        "valid recovery still succeeds after rejection"
      );
    }
    t.end();
  });

  test(`recover backend rejects invalid recovery IDs (${type})`, (t) => {
    const expected = secp256k1.pointFromScalar(privateKey, true);
    for (const recoveryId of [-1, 4]) {
      t.equal(
        backend.recover(33, recoveryId),
        0x780,
        `returns the recovery-ID error code for ${recoveryId}`
      );
      t.same(
        secp256k1.recover(hash, signature, f.recoveryId, true),
        expected,
        "valid recovery still succeeds after backend rejection"
      );
    }
    t.end();
  });
}
