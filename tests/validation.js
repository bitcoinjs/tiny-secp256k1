import test from "tape";
import { fromHex } from "./util.js";
import fecdsa from "./fixtures/ecdsa.json" assert { type: "json" };

export default function (secp256k1, type) {
  test(`point validation preserves subsequent operations (${type})`, (t) => {
    const f = fecdsa.valid[0];
    const hash = fromHex(f.m);
    const signature = fromHex(f.signature);
    const privateKey = fromHex(f.d);
    const point = secp256k1.pointFromScalar(privateKey, true);
    const xOnlyPoint = point.slice(1);
    const invalidPoint = new Uint8Array(33).fill(0xff);
    invalidPoint[0] = 2;
    const invalidXOnlyPoint = invalidPoint.slice(1);
    const tweak = new Uint8Array(32);
    const cases = [
      ["pointAdd first point", () => secp256k1.pointAdd(invalidPoint, point)],
      ["pointAdd second point", () => secp256k1.pointAdd(point, invalidPoint)],
      ["pointCompress", () => secp256k1.pointCompress(invalidPoint)],
      [
        "pointMultiply",
        () => secp256k1.pointMultiply(invalidPoint, privateKey),
      ],
      ["pointAddScalar", () => secp256k1.pointAddScalar(invalidPoint, tweak)],
      [
        "xOnlyPointFromPoint",
        () => secp256k1.xOnlyPointFromPoint(invalidPoint),
      ],
      ["verify", () => secp256k1.verify(hash, invalidPoint, signature)],
      [
        "verifySchnorr",
        () => secp256k1.verifySchnorr(hash, invalidXOnlyPoint, signature),
      ],
      [
        "xOnlyPointAddTweak",
        () => secp256k1.xOnlyPointAddTweak(invalidXOnlyPoint, tweak),
      ],
    ];
    for (const parity of [undefined, 0, 1]) {
      cases.push([
        `xOnlyPointAddTweakCheck parity ${parity}`,
        () =>
          secp256k1.xOnlyPointAddTweakCheck(
            invalidXOnlyPoint,
            tweak,
            xOnlyPoint,
            parity
          ),
      ]);
    }
    cases.push([
      "xOnlyPointAddTweakCheck result point",
      () =>
        secp256k1.xOnlyPointAddTweakCheck(
          xOnlyPoint,
          tweak,
          invalidXOnlyPoint,
          0
        ),
    ]);
    for (const [name, reject] of cases) {
      t.throws(
        reject,
        (error) =>
          error instanceof TypeError && error.message === "Expected Point",
        `${name} returns a validation error`
      );
      t.same(
        secp256k1.sign(hash, privateKey),
        signature,
        "valid signing still matches the fixture after rejection"
      );
      t.equal(
        secp256k1.verify(hash, point, signature),
        true,
        "valid verification still succeeds after rejection"
      );
    }
    t.end();
  });
}
