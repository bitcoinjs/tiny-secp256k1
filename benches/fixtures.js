import * as crypto from "crypto";
import * as tiny_secp256k1 from "../lib/index.js";
import _fecdsa from "../tests/fixtures/ecdsa.json" assert { type: "json" };
import _fpoints from "../tests/fixtures/points.json" assert { type: "json" };
import _fprivates from "../tests/fixtures/privates.json" assert { type: "json" };
import _fschnorr from "../tests/fixtures/schnorr.json" assert { type: "json" };
import { parseBip340Vector } from "../tests/schnorr.js";

const randPubKey = () =>
  tiny_secp256k1.xOnlyPointFromScalar(Uint8Array.from(crypto.randomBytes(32)));

export const fecdsa = _fecdsa.valid.map((f) => ({
  d: Buffer.from(f.d, "hex"),
  Q: Buffer.from(tiny_secp256k1.pointFromScalar(Buffer.from(f.d, "hex"))),
  m: Buffer.from(f.m, "hex"),
  signature: Buffer.from(f.signature, "hex"),
}));

export const fpoints = {
  isPoint: _fpoints.valid.isPoint.map((f) => ({
    P: Buffer.from(f.P, "hex"),
  })),
  pointAdd: _fpoints.valid.pointAdd
    .filter((f) => f.expected !== null)
    .map((f) => ({
      P: Buffer.from(f.P, "hex"),
      Q: Buffer.from(f.Q, "hex"),
    })),
  pointAddScalar: _fpoints.valid.pointAddScalar
    .filter((f) => f.expected !== null)
    .map((f) => ({
      P: Buffer.from(f.P, "hex"),
      d: Buffer.from(f.d, "hex"),
    })),
  pointCompress: _fpoints.valid.pointCompress.map((f) => ({
    P: Buffer.from(f.P, "hex"),
  })),
  pointFromScalar: _fpoints.valid.pointFromScalar.map((f) => ({
    d: Buffer.from(f.d, "hex"),
  })),
  pointMultiply: _fpoints.valid.pointMultiply
    .filter((f) => f.expected !== null)
    .map((f) => ({
      P: Buffer.from(f.P, "hex"),
      d: Buffer.from(f.d, "hex"),
    })),
};

export const fprivates = {
  isPrivate: _fprivates.valid.isPrivate.map((f) => ({
    d: Buffer.from(f.d, "hex"),
  })),
  privateAdd: _fprivates.valid.privateAdd
    .filter((f) => f.expected !== null)
    .map((f) => ({
      d: Buffer.from(f.d, "hex"),
      tweak: Buffer.from(f.tweak, "hex"),
    })),
  privateSub: _fprivates.valid.privateSub
    .filter((f) => f.expected !== null)
    .map((f) => ({
      d: Buffer.from(f.d, "hex"),
      tweak: Buffer.from(f.tweak, "hex"),
    })),
};

export const fschnorrSign = _fschnorr.bip340testvectors
  .filter((f) => !f.exception)
  .filter((f) => !!f.d)
  .map(parseBip340Vector)
  .map((res) => {
    res.pubkey = tiny_secp256k1.pointFromScalar(res.d, true);
    return res;
  });

export const fschnorrVerify = _fschnorr.bip340testvectors
  .filter((f) => !f.exception)
  .map(parseBip340Vector);

export const fschnorrTweak = new Array(50).fill(1).map(() => {
  const res = {
    Q: randPubKey(),
    tweak: randPubKey(),
    dummy: randPubKey(),
  };
  const output = tiny_secp256k1.xOnlyPointAddTweak(res.Q, res.tweak);
  res.output = output.xOnlyPubkey;
  res.parity = output.parity;
  return res;
});
