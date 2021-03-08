const tape = require("tape");
const { fromHex } = require("./util");
const fpoints = require("./fixtures/points.json");

function test(binding) {
  tape("isPoint", (t) => {
    for (const f of fpoints.valid.isPoint) {
      const p = fromHex(f.P);
      t.equal(
        binding.isPoint(p),
        f.expected,
        `${f.P} is ${f.expected ? "OK" : "rejected"}`
      );
    }

    t.end();
  });

  tape("isPointCompressed", (t) => {
    for (const f of fpoints.valid.isPoint) {
      if (!f.expected) continue;
      const p = fromHex(f.P);
      const e = p.length === 33;
      t.equal(
        binding.isPointCompressed(p),
        e,
        `${f.P} is ${e ? "compressed" : "uncompressed"}`
      );
    }

    t.end();
  });

  tape("pointAdd", (t) => {
    for (const f of fpoints.valid.pointAdd) {
      const p = fromHex(f.P);
      const q = fromHex(f.Q);
      const expected = f.expected ? fromHex(f.expected) : null;
      let description = `${f.P} + ${f.Q} = ${f.expected ? f.expected : null}`;
      if (f.description) description += ` (${f.description})`;
      t.same(binding.pointAdd(p, q), expected, description);
      if (expected === null) continue;
      t.same(
        binding.pointAdd(p, q, true),
        binding.pointCompress(expected, true),
        description
      );
      t.same(
        binding.pointAdd(p, q, false),
        binding.pointCompress(expected, false),
        description
      );
    }

    for (const f of fpoints.invalid.pointAdd) {
      const p = fromHex(f.P);
      const q = fromHex(f.Q);
      t.throws(
        () => {
          binding.pointAdd(p, q);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  tape("pointAddScalar", (t) => {
    for (const f of fpoints.valid.pointAddScalar) {
      const p = fromHex(f.P);
      const d = fromHex(f.d);
      const expected = f.expected ? fromHex(f.expected) : null;
      let description = `${f.P} + ${f.d} = ${f.expected ? f.expected : null}`;
      if (f.description) description += ` (${f.description})`;
      t.same(binding.pointAddScalar(p, d), expected, description);
      if (expected === null) continue;
      t.same(
        binding.pointAddScalar(p, d, true),
        binding.pointCompress(expected, true),
        description
      );
      t.same(
        binding.pointAddScalar(p, d, false),
        binding.pointCompress(expected, false),
        description
      );
    }

    for (const f of fpoints.invalid.pointAddScalar) {
      const p = fromHex(f.P);
      const d = fromHex(f.d);
      t.throws(
        () => {
          binding.pointAddScalar(p, d);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  tape("pointCompress", (t) => {
    for (const f of fpoints.valid.pointCompress) {
      const p = fromHex(f.P);
      const expected = fromHex(f.expected);
      if (f.noarg) {
        t.same(binding.pointCompress(p), expected);
      } else {
        t.same(binding.pointCompress(p, f.compress), expected);
      }
    }

    for (const f of fpoints.invalid.pointCompress) {
      const p = fromHex(f.P);
      t.throws(
        () => {
          binding.pointCompress(p);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  tape("pointFromScalar", (t) => {
    for (const f of fpoints.valid.pointFromScalar) {
      const d = fromHex(f.d);
      const expected = fromHex(f.expected);
      let description = `${f.d} * G = ${f.expected}`;
      if (f.description) description += ` (${f.description})`;
      t.same(binding.pointFromScalar(d), expected, description);
      if (expected === null) continue;
      t.same(
        binding.pointFromScalar(d, true),
        binding.pointCompress(expected, true),
        description
      );
      t.same(
        binding.pointFromScalar(d, false),
        binding.pointCompress(expected, false),
        description
      );
    }

    for (const f of fpoints.invalid.pointFromScalar) {
      const d = fromHex(f.d);
      t.throws(
        () => {
          binding.pointFromScalar(d);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  tape("pointMultiply", (t) => {
    for (const f of fpoints.valid.pointMultiply) {
      const p = fromHex(f.P);
      const d = fromHex(f.d);
      const expected = f.expected ? fromHex(f.expected) : null;
      let description = `${f.P} * ${f.d} = ${f.expected ? f.expected : null}`;
      if (f.description) description += ` (${f.description})`;
      t.same(binding.pointMultiply(p, d), expected, description);
      if (expected === null) continue;
      t.same(
        binding.pointMultiply(p, d, true),
        binding.pointCompress(expected, true),
        description
      );
      t.same(
        binding.pointMultiply(p, d, false),
        binding.pointCompress(expected, false),
        description
      );
    }

    for (const f of fpoints.invalid.pointMultiply) {
      const p = fromHex(f.P);
      const d = fromHex(f.d);
      t.throws(
        () => {
          binding.pointMultiply(p, d);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });
}

module.exports = test;
