import tiny_secp256k1_prev_js from "tiny-secp256k1/js.js";
import tiny_secp256k1_prev_native from "tiny-secp256k1/native.js";
import * as tiny_secp256k1 from "../lib/index.js";
import * as cryptocoinjs_secp256k1 from "./cryptocoinjs_secp256k1.js";
import { fecdsa, fpoints, fprivates } from "./fixtures.js";

const modules = [
  {
    name: "tiny-secp256k1 (rust addon)",
    secp256k1: tiny_secp256k1.__addon,
  },
  {
    name: "tiny-secp256k1 (wasm)",
    secp256k1: tiny_secp256k1.__wasm,
  },
  {
    name: "tiny-secp256k1@1.1.6 (C++ addon, NAN/V8)",
    secp256k1: tiny_secp256k1_prev_native,
  },
  {
    name: "tiny-secp256k1@1.1.6 (elliptic)",
    secp256k1: tiny_secp256k1_prev_js,
  },
  {
    name: "secp256k1@4.0.2 (C++ addon, N-API)",
    secp256k1: cryptocoinjs_secp256k1.native,
  },
  {
    name: "secp256k1@4.0.2 (elliptic)",
    secp256k1: cryptocoinjs_secp256k1.js,
  },
];

const benchmarks = [
  {
    name: "isPoint",
    bench: createBenchmarkFn(fpoints.isPoint, (secp256k1, f) =>
      secp256k1.isPoint(f.P)
    ),
  },
  {
    name: "isPrivate",
    bench: createBenchmarkFn(fprivates.isPrivate, (secp256k1, f) =>
      secp256k1.isPrivate(f.d)
    ),
  },
  {
    name: "pointAdd",
    bench: createBenchmarkFn(fpoints.pointAdd, (secp256k1, f) =>
      secp256k1.pointAdd(f.P, f.Q)
    ),
  },
  {
    name: "pointAddScalar",
    bench: createBenchmarkFn(fpoints.pointAddScalar, (secp256k1, f) =>
      secp256k1.pointAddScalar(f.P, f.d)
    ),
  },
  {
    name: "pointCompress",
    bench: createBenchmarkFn(fpoints.pointCompress, (secp256k1, f) =>
      secp256k1.pointCompress(f.P)
    ),
  },
  {
    name: "pointFromScalar",
    bench: createBenchmarkFn(fpoints.pointFromScalar, (secp256k1, f) =>
      secp256k1.pointFromScalar(f.d)
    ),
  },
  {
    name: "pointMultiply",
    bench: createBenchmarkFn(fpoints.pointMultiply, (secp256k1, f) =>
      secp256k1.pointMultiply(f.P, f.d)
    ),
  },
  {
    name: "privateAdd",
    bench: createBenchmarkFn(fprivates.privateAdd, (secp256k1, f) =>
      secp256k1.privateAdd(f.d, f.tweak)
    ),
  },
  {
    name: "privateSub",
    bench: createBenchmarkFn(fprivates.privateSub, (secp256k1, f) =>
      secp256k1.privateSub(f.d, f.tweak)
    ),
  },
  {
    name: "sign",
    bench: createBenchmarkFn(fecdsa, (secp256k1, f) =>
      secp256k1.sign(f.m, f.d)
    ),
  },
  {
    name: "verify",
    bench: createBenchmarkFn(fecdsa, (secp256k1, f) =>
      secp256k1.verify(f.m, f.Q, f.signature)
    ),
  },
];

// Covert milliseconds as Number to nanoseconds as BigInt
const millis2nanos = (ms) => BigInt(ms) * 10n ** 6n;

// Warmup bench function during
function warmingUp(bench, minIter, maxTime) {
  const start = process.hrtime.bigint();
  for (let i = 0; ; ) {
    bench();
    if (process.hrtime.bigint() - start > maxTime && ++i >= minIter) {
      break;
    }
  }
}

// Create benchmark function from fixtures
function createBenchmarkFn(fixtures, fn) {
  return function (secp256k1) {
    for (const f of fixtures) {
      fn(secp256k1, f);
    }
    return fixtures.length;
  };
}

// Run benchmarks
const lineEqual = new Array(100).fill("=").join("");
const lineDash = new Array(100).fill("-").join("");
let isFirstResult = true;
for (const benchmark of benchmarks) {
  const {
    name,
    bench,
    warmingUpMinIter,
    warmingUpMaxTime,
    benchmarkMinIter,
    benchmarkMaxTime,
  } = {
    warmingUpMinIter: 1,
    benchmarkMinIter: 2,
    warmingUpMaxTime: millis2nanos(2000),
    benchmarkMaxTime: millis2nanos(5000),
    ...benchmark,
  };

  if (isFirstResult) {
    console.log(lineEqual);
    isFirstResult = false;
  }
  console.log(`Benchmarking function: ${name}`);
  console.log(lineDash);
  const results = [];
  for (const module of modules) {
    if (module.secp256k1[name] === undefined) {
      continue;
    }

    warmingUp(
      () => bench(module.secp256k1),
      warmingUpMinIter,
      warmingUpMaxTime
    );

    const results_ns = [];
    const start = process.hrtime.bigint();
    let start_fn = start;
    for (let i = 0; ; ) {
      const ops = bench(module.secp256k1);
      const current = process.hrtime.bigint();
      results_ns.push(Number(current - start_fn) / ops);
      if (current - start > benchmarkMaxTime && ++i >= benchmarkMinIter) {
        break;
      }
      start_fn = current;
    }

    const ops_avg_ns =
      results_ns.reduce((total, time) => total + time, 0) / results_ns.length;
    const ops_err_ns =
      results_ns.length > 1
        ? results_ns.reduce(
            (total, time) => total + Math.abs(ops_avg_ns - time),
            0
          ) /
          (results_ns.length - 1)
        : 0;
    const ops_err = (ops_err_ns / ops_avg_ns) * 100;

    console.log(
      `${module.name}: ${(ops_avg_ns / 1000).toFixed(2)} us/op (${(
        10 ** 9 /
        ops_avg_ns
      ).toFixed(2)} op/s), ±${ops_err.toFixed(2)} %`
    );

    results.push({ name: module.name, ops_avg_ns });
  }
  if (results.length > 1) {
    const fastest = results.reduce((a, b) =>
      a.ops_avg_ns < b.ops_avg_ns ? a : b
    );
    console.log(lineDash);
    console.log(`Fastest: ${fastest.name}`);
  }
  console.log(lineEqual);
}
