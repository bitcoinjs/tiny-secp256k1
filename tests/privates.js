import { test } from "tape";
import { fromHex } from "./util.js";
import fprivates from "./fixtures/privates.json";

export default function (binding) {
  test("isPrivate", (t) => {
    for (const f of fprivates.valid.isPrivate) {
      const d = fromHex(f.d);

      t.equal(
        binding.isPrivate(d),
        f.expected,
        `${f.d} is ${f.expected ? "OK" : "rejected"}`
      );
    }

    t.end();
  });

  test("privateAdd", (t) => {
    for (const f of fprivates.valid.privateAdd) {
      const d = fromHex(f.d);
      const tweak = fromHex(f.tweak);
      const expected = f.expected ? fromHex(f.expected) : null;
      let description = `${f.d} + ${f.tweak} = ${
        f.expected ? f.expected : null
      }`;
      if (f.description) description += ` (${f.description})`;

      t.same(binding.privateAdd(d, tweak), expected, description);
    }

    for (const f of fprivates.invalid.privateAdd) {
      const d = fromHex(f.d);
      const tweak = fromHex(f.tweak);

      t.throws(
        () => {
          binding.privateAdd(d, tweak);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });

  test("privateSub", (t) => {
    for (const f of fprivates.valid.privateSub) {
      const d = fromHex(f.d);
      const tweak = fromHex(f.tweak);
      const expected = f.expected ? fromHex(f.expected) : null;
      let description = `${f.d} - ${f.tweak} = ${
        f.expected ? f.expected : null
      }`;
      if (f.description) description += ` (${f.description})`;

      t.same(binding.privateSub(d, tweak), expected, description);
    }

    for (const f of fprivates.invalid.privateSub) {
      const d = fromHex(f.d);
      const tweak = fromHex(f.tweak);

      t.throws(
        () => {
          binding.privateSub(d, tweak);
        },
        new RegExp(f.exception),
        `${f.description} throws ${f.exception}`
      );
    }

    t.end();
  });
}
