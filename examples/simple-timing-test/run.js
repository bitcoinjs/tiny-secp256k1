import { fromHex } from "uint8array-tools";
import * as secp256k1 from "../../lib/index.js";

const TWO = fromHex("0".repeat(63) + "2");
const TOP_BIT = fromHex("8" + "0".repeat(63));
const N_LESS_ONE = fromHex(
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
);

const ITER = 10000;

const BENCHES = [
  {
    name: "Privkey two",
    func() {
      secp256k1.pointFromScalar(TWO);
    },
  },
  {
    name: "Highest bit",
    func() {
      secp256k1.pointFromScalar(TOP_BIT);
    },
  },
  {
    name: "Max privkey",
    func() {
      secp256k1.pointFromScalar(N_LESS_ONE);
    },
  },
];

function warmup() {
  for (let i = 0; i < 4000; i++) {
    BENCHES[0].func();
  }
}

function bench(name, f, iter) {
  const start = process.hrtime.bigint();
  for (let i = 0; i < iter; i++) {
    f();
  }
  const end = process.hrtime.bigint();
  const duration = end - start;
  console.log(`${name}: ${(duration / BigInt(iter)).toString(10)} ns per op`);
  return duration;
}

async function main() {
  warmup();
  const durations = BENCHES.map((b) => bench(b.name, b.func, ITER)).map(
    (v) => v / BigInt(1e6)
  );
  durations.sort();
  const [hi, low] = [
    Number(durations[durations.length - 1]),
    Number(durations[0]),
  ];
  const hiLowDiff = hi - low;
  const avg = (hi + low) / 2;
  const pct = (hi / avg - 1) * 100;
  console.log(`High Low Diff: ${hiLowDiff} ms diff for ${ITER} iterations`);
  console.log(`±${pct.toFixed(2)}% variance`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
