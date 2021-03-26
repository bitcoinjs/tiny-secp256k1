import * as tiny_secp256k1 from "../";
import _fecdsa from "../tests/fixtures/ecdsa.json";
import _fpoints from "../tests/fixtures/points.json";
import _fprivates from "../tests/fixtures/privates.json";

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
