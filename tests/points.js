import test from "tape";
import { fromHex } from "./util.js";
import fpoints from "./fixtures/points.json";

export default function (secp256k1) {
  test("isPoint", (t) => {
    for (const f of fpoints.valid.isPoint) {
      const p = fromHex(f.P);
      t.equal(
        secp256k1.isPoint(p),
        f.expected,
        `${f.P} is ${f.expected ? "OK" : "rejected"}`
      );
    }

    t.end();
  });

  test("isPointCompressed", (t) => {
    for (const f of fpoints.valid.isPoint) {
      if (!f.expected) continue;
      const p = fromHex(f.P);
      const e = p.length === 33;
      t.equal(
        secp256k1.isPointCompressed(p),
        e,
        `${f.P} is ${e ? "compressed" : "uncompressed"}`
      );
    }

    t.end();
  });

  test("isXOnlyPoint", (t) => {
    for (const f of fpoints.valid.isPoint) {
      if (!f.expected) continue;
      const p = fromHex(f.P);
      const e = p.length === 33;
      const p2 = e ? p.slice(1, 33) : p;
      t.equal(
        secp256k1.isXOnlyPoint(p2),
        e,
        `${f.P} is ${e ? "xonly" : "uncompressed"}`
      );
    }

    t.end();
  });

  test("pointAdd", (t) => {
    for (const f of fpoints.valid.pointAdd) {
      const p = fromHex(f.P);
      const q = fromHex(f.Q);
      const expected = f.expected ? fromHex(f.expected) : null;
      let description = `${f.P} + ${f.Q} = ${f.expected ? f.expected : null}`;
      if (f.description) description += ` (${f.description})`;
      t.same(secp256k1.pointAdd(p, q), expected, description);
      if (expected === null) continue;
      t.same(
        secp256k1.pointAdd(p, q, true),
        secp256k1.pointCompress(expected, true),
        description
      );
      t.same(
        secp256k1.pointAdd(p, q, false),
        secp256k1.pointCompress(expected, false),
        description
      );
    }

    for (const f of fpoints.invalid.pointAdd) {
      const p = fromHex(f.P);
      const q = fromHex(f.Q);
      t.throws(
        () => {
          secp256k1.pointAdd(p, q);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  test("pointAddScalar", (t) => {
    for (const f of fpoints.valid.pointAddScalar) {
      const p = fromHex(f.P);
      const d = fromHex(f.d);
      const expected = f.expected ? fromHex(f.expected) : null;
      let description = `${f.P} + ${f.d} = ${f.expected ? f.expected : null}`;
      if (f.description) description += ` (${f.description})`;
      t.same(secp256k1.pointAddScalar(p, d), expected, description);
      if (expected === null) continue;
      t.same(
        secp256k1.pointAddScalar(p, d, true),
        secp256k1.pointCompress(expected, true),
        description
      );
      t.same(
        secp256k1.pointAddScalar(p, d, false),
        secp256k1.pointCompress(expected, false),
        description
      );
    }

    for (const f of fpoints.invalid.pointAddScalar) {
      const p = fromHex(f.P);
      const d = fromHex(f.d);
      t.throws(
        () => {
          secp256k1.pointAddScalar(p, d);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  test("pointCompress", (t) => {
    for (const f of fpoints.valid.pointCompress) {
      const p = fromHex(f.P);
      const expected = fromHex(f.expected);
      if (f.noarg) {
        t.same(secp256k1.pointCompress(p), expected);
      } else {
        t.same(secp256k1.pointCompress(p, f.compress), expected);
      }
    }

    for (const f of fpoints.invalid.pointCompress) {
      const p = fromHex(f.P);
      t.throws(
        () => {
          secp256k1.pointCompress(p);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  test("pointFromScalar", (t) => {
    for (const f of fpoints.valid.pointFromScalar) {
      const d = fromHex(f.d);
      const expected = fromHex(f.expected);
      let description = `${f.d} * G = ${f.expected}`;
      if (f.description) description += ` (${f.description})`;
      t.same(secp256k1.pointFromScalar(d), expected, description);
      if (expected === null) continue;
      t.same(
        secp256k1.pointFromScalar(d, true),
        secp256k1.pointCompress(expected, true),
        description
      );
      t.same(
        secp256k1.pointFromScalar(d, false),
        secp256k1.pointCompress(expected, false),
        description
      );
    }

    for (const f of fpoints.invalid.pointFromScalar) {
      const d = fromHex(f.d);
      t.throws(
        () => {
          secp256k1.pointFromScalar(d);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  test("pointMultiply", (t) => {
    for (const f of fpoints.valid.pointMultiply) {
      const p = fromHex(f.P);
      const d = fromHex(f.d);
      const expected = f.expected ? fromHex(f.expected) : null;
      let description = `${f.P} * ${f.d} = ${f.expected ? f.expected : null}`;
      if (f.description) description += ` (${f.description})`;
      t.same(secp256k1.pointMultiply(p, d), expected, description);
      if (expected === null) continue;
      t.same(
        secp256k1.pointMultiply(p, d, true),
        secp256k1.pointCompress(expected, true),
        description
      );
      t.same(
        secp256k1.pointMultiply(p, d, false),
        secp256k1.pointCompress(expected, false),
        description
      );
    }

    for (const f of fpoints.invalid.pointMultiply) {
      const p = fromHex(f.P);
      const d = fromHex(f.d);
      t.throws(
        () => {
          secp256k1.pointMultiply(p, d);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  test("pointNegate", (t) => {
    for (const f of fpoints.valid.pointNegate) {
      const d = fromHex(f.d);
      const expected = fromHex(f.expected);
      let description = `-${f.d} = ${f.expected}`;
      if (f.description) description += ` (${f.description})`;
      t.same(secp256k1.privateNegate(d), expected, description);

      t.equal(secp256k1.privateAdd(d, expected), null, description);
    }

    // using the same data as point from scalar
    for (const f of fpoints.invalid.pointFromScalar) {
      const d = fromHex(f.d);
      t.throws(
        () => {
          secp256k1.privateNegate(d);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });
}
