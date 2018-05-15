let bigi = require('bigi')
let createHmac = require('create-hmac')
let ecurve = require('ecurve')
let secp256k1 = ecurve.getCurveByName('secp256k1')

let ZERO32 = Buffer.alloc(32, 0)
let EC_GROUP_ORDER = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')
let EC_P = Buffer.from('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 'hex')

let ONE1 = Buffer.alloc(1, 1)
let ZERO1 = Buffer.alloc(1, 0)

let THROW_BAD_PRIVATE = 'Expected Private'
let THROW_BAD_POINT = 'Expected Point'
let THROW_BAD_TWEAK = 'Expected Tweak'
let THROW_BAD_HASH = 'Expected Hash'
let THROW_BAD_SIGNATURE = 'Expected Signature'

function isScalar (x) {
  return Buffer.isBuffer(x) && x.length === 32
}

function isOrderScalar (x) {
  if (!isScalar(x)) return false
  return x.compare(EC_GROUP_ORDER) < 0 // < G
}

function isPoint (p) {
  if (!Buffer.isBuffer(p)) return false
  if (p.length < 33) return false

  let t = p[0]
  let x = p.slice(1, 33)
  if (x.compare(ZERO32) === 0) return false
  if (x.compare(EC_P) >= 0) return false
  if ((t === 0x02 || t === 0x03) && p.length === 33) return true

  let y = p.slice(33)
  if (y.compare(ZERO32) === 0) return false
  if (y.compare(EC_P) >= 0) return false
  if (t === 0x04 && p.length === 65) return true
  return false
}

function __isPointCompressed (p) {
  return p[0] !== 0x04
}

function isPointCompressed (p) {
  if (!isPoint(p)) return false
  return __isPointCompressed(p)
}

function isPrivate (x) {
  if (!isScalar(x)) return false
  return x.compare(ZERO32) > 0 && // > 0
    x.compare(EC_GROUP_ORDER) < 0 // < G
}

function isSignature (value) {
  let r = value.slice(0, 32)
  let s = value.slice(32, 64)
  return Buffer.isBuffer(value) && value.length === 64 &&
    r.compare(EC_GROUP_ORDER) < 0 &&
    s.compare(EC_GROUP_ORDER) < 0
}

function assumeCompression (value, pubkey) {
  if (value === undefined && pubkey !== undefined) return __isPointCompressed(pubkey)
  if (value === undefined) return true
  return value
}

function pointAdd (pA, pB, __compressed) {
  if (!isPoint(pA)) throw new TypeError(THROW_BAD_POINT)
  if (!isPoint(pB)) throw new TypeError(THROW_BAD_POINT)

  let a = ecurve.Point.decodeFrom(secp256k1, pA)
  let b = ecurve.Point.decodeFrom(secp256k1, pB)
  let pp = a.add(b)
  if (secp256k1.isInfinity(pp)) return null

  let compressed = assumeCompression(__compressed, pA)
  return pp.getEncoded(compressed)
}

function pointAddScalar (p, tweak, __compressed) {
  if (!isPoint(p)) throw new TypeError(THROW_BAD_POINT)
  if (!isOrderScalar(tweak)) throw new TypeError(THROW_BAD_TWEAK)

  let compressed = assumeCompression(__compressed, p)
  let pp = ecurve.Point.decodeFrom(secp256k1, p)
  if (tweak.compare(ZERO32) === 0) return pp.getEncoded(compressed)

  let tt = bigi.fromBuffer(tweak)
  let qq = secp256k1.G.multiply(tt)
  let uu = pp.add(qq)
  if (secp256k1.isInfinity(uu)) return null

  return uu.getEncoded(compressed)
}

function pointCompress (p, compressed) {
  if (!isPoint(p)) throw new TypeError(THROW_BAD_POINT)

  let pp = ecurve.Point.decodeFrom(secp256k1, p)
  if (secp256k1.isInfinity(pp)) throw new TypeError(THROW_BAD_POINT)

  return pp.getEncoded(compressed)
}

function pointFromScalar (d, __compressed) {
  if (!isPrivate(d)) throw new TypeError(THROW_BAD_PRIVATE)

  let dd = bigi.fromBuffer(d)
  let pp = secp256k1.G.multiply(dd)
  if (secp256k1.isInfinity(pp)) return null

  let compressed = assumeCompression(__compressed)
  return pp.getEncoded(compressed)
}

function pointMultiply (p, tweak, __compressed) {
  if (!isPoint(p)) throw new TypeError(THROW_BAD_POINT)
  if (!isOrderScalar(tweak)) throw new TypeError(THROW_BAD_TWEAK)

  let compressed = assumeCompression(__compressed, p)
  let pp = ecurve.Point.decodeFrom(secp256k1, p)
  let tt = bigi.fromBuffer(tweak)
  let qq = pp.multiply(tt)
  if (secp256k1.isInfinity(qq)) return null

  return qq.getEncoded(compressed)
}

function privateAdd (d, tweak) {
  if (!isPrivate(d)) throw new TypeError(THROW_BAD_PRIVATE)
  if (!isOrderScalar(tweak)) throw new TypeError(THROW_BAD_TWEAK)

  let dd = bigi.fromBuffer(d)
  let tt = bigi.fromBuffer(tweak)
  let dt = dd.add(tt).mod(secp256k1.n).toBuffer(32)
  if (!isPrivate(dt)) return null

  return dt
}

function privateSub (d, tweak) {
  if (!isPrivate(d)) throw new TypeError(THROW_BAD_PRIVATE)
  if (!isOrderScalar(tweak)) throw new TypeError(THROW_BAD_TWEAK)

  let dd = bigi.fromBuffer(d)
  let tt = bigi.fromBuffer(tweak)
  let dt = dd.subtract(tt).mod(secp256k1.n).toBuffer(32)
  if (!isPrivate(dt)) return null

  return dt
}

// https://tools.ietf.org/html/rfc6979#section-3.2
function deterministicGenerateK (hash, x, checkSig) {
  // Step A, ignored as hash already provided
  // Step B
  // Step C
  let k = Buffer.alloc(32, 0)
  let v = Buffer.alloc(32, 1)

  // Step D
  k = createHmac('sha256', k)
    .update(v)
    .update(ZERO1)
    .update(x)
    .update(hash)
    .digest()

  // Step E
  v = createHmac('sha256', k).update(v).digest()

  // Step F
  k = createHmac('sha256', k)
    .update(v)
    .update(ONE1)
    .update(x)
    .update(hash)
    .digest()

  // Step G
  v = createHmac('sha256', k).update(v).digest()

  // Step H1/H2a, ignored as tlen === qlen (256 bit)
  // Step H2b
  v = createHmac('sha256', k).update(v).digest()

  let T = bigi.fromBuffer(v)

  // Step H3, repeat until T is within the interval [1, n - 1] and is suitable for ECDSA
  while (T.signum() <= 0 || T.compareTo(secp256k1.n) >= 0 || !checkSig(T)) {
    k = createHmac('sha256', k)
      .update(v)
      .update(ZERO1)
      .digest()

    v = createHmac('sha256', k).update(v).digest()

    // Step H1/H2a, again, ignored as tlen === qlen (256 bit)
    // Step H2b again
    v = createHmac('sha256', k).update(v).digest()
    T = bigi.fromBuffer(v)
  }

  return T
}

let N_OVER_TWO = secp256k1.n.shiftRight(1)

function sign (hash, x) {
  if (!isScalar(hash)) throw new TypeError(THROW_BAD_HASH)
  if (!isPrivate(x)) throw new TypeError(THROW_BAD_PRIVATE)

  let d = bigi.fromBuffer(x)
  let e = bigi.fromBuffer(hash)
  let n = secp256k1.n
  let G = secp256k1.G

  let r, s
  deterministicGenerateK(hash, x, function (k) {
    let Q = G.multiply(k)

    if (secp256k1.isInfinity(Q)) return false

    r = Q.affineX.mod(n)
    if (r.signum() === 0) return false

    s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n)
    if (s.signum() === 0) return false

    return true
  })

  // enforce low S values, see bip62: 'low s values in signatures'
  if (s.compareTo(N_OVER_TWO) > 0) {
    s = n.subtract(s)
  }

  let buffer = Buffer.allocUnsafe(64)
  r.toBuffer(32).copy(buffer, 0)
  s.toBuffer(32).copy(buffer, 32)
  return buffer
}

function verify (hash, q, signature) {
  if (!isScalar(hash)) throw new TypeError(THROW_BAD_HASH)
  if (!isPoint(q)) throw new TypeError(THROW_BAD_POINT)

  // 1.4.1 Enforce r and s are both integers in the interval [1, n − 1] (1, isSignature enforces '< n - 1')
  if (!isSignature(signature)) throw new TypeError(THROW_BAD_SIGNATURE)

  let Q = ecurve.Point.decodeFrom(secp256k1, q)
  let n = secp256k1.n
  let G = secp256k1.G
  let r = bigi.fromBuffer(signature.slice(0, 32))
  let s = bigi.fromBuffer(signature.slice(32, 64))

  // 1.4.1 Enforce r and s are both integers in the interval [1, n − 1] (2, enforces '> 0')
  if (r.signum() <= 0 /* || r.compareTo(n) >= 0 */) return false
  if (s.signum() <= 0 /* || s.compareTo(n) >= 0 */) return false

  // 1.4.2 H = Hash(M), already done by the user
  // 1.4.3 e = H
  let e = bigi.fromBuffer(hash)

  // Compute s^-1
  let sInv = s.modInverse(n)

  // 1.4.4 Compute u1 = es^−1 mod n
  //               u2 = rs^−1 mod n
  let u1 = e.multiply(sInv).mod(n)
  let u2 = r.multiply(sInv).mod(n)

  // 1.4.5 Compute R = (xR, yR)
  //               R = u1G + u2Q
  let R = G.multiplyTwo(u1, Q, u2)

  // 1.4.5 (cont.) Enforce R is not at infinity
  if (secp256k1.isInfinity(R)) return false

  // 1.4.6 Convert the field element R.x to an integer
  let xR = R.affineX

  // 1.4.7 Set v = xR mod n
  let v = xR.mod(n)

  // 1.4.8 If v = r, output "valid", and if v != r, output "invalid"
  return v.equals(r)
}

module.exports = {
  isPoint,
  isPointCompressed,
  isPrivate,
  pointAdd,
  pointAddScalar,
  pointCompress,
  pointFromScalar,
  pointMultiply,
  privateAdd,
  privateSub,
  sign,
  verify
}
