let bigi = require('bigi')
let createHmac = require('create-hmac')
let ecurve = require('ecurve')
let secp256k1 = ecurve.getCurveByName('secp256k1')

let EC_ZERO = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
let EC_UINT_MAX = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')
let ONE1 = Buffer.alloc(1, 1)
let ZERO1 = Buffer.alloc(1, 0)

function isUInt256 (value) {
  return Buffer.isBuffer(value) && value.length === 32
}

function isPoint (q) {
  if (!Buffer.isBuffer(q)) return false
  if (q.length < 33) return false

  let t = q[0]
  if ((t === 0x02 || t === 0x03) && q.length === 33) return true
  if (t === 0x04 && q.length === 65) return true
  return false
}

function isPrivate (value) {
  if (!isUInt256(value)) return false
  return value.compare(EC_ZERO) > 0 && // > 0
    value.compare(EC_UINT_MAX) < 0 // < n-1
}

function isSignature (value) {
  return Buffer.isBuffer(value) && value.length === 64
}

function pointAdd (pA, pB, compressed) {
  if (!isPoint(pA)) throw new TypeError('Expected Point')
  if (!isPoint(pB)) throw new TypeError('Expected Point')
  let a = ecurve.Point.decodeFrom(secp256k1, pA)
  let b = ecurve.Point.decodeFrom(secp256k1, pB)
  let p = a.add(b)
  if (secp256k1.isInfinity(p)) return null
  return p.getEncoded(compressed)
}

function pointAddScalar (p, tweak, compressed) {
  if (!isPoint(p)) throw new TypeError('Expected Point')
  if (!isPrivate(tweak)) throw new TypeError('Expected Tweak')
  let q = ecurve.Point.decodeFrom(secp256k1, p)
  let u = q.multiply(tweak)
  if (secp256k1.isInfinity(u)) return null
  return u.getEncoded(compressed)
}

function pointCompress (p, compressed) {
  if (!isPoint(p)) throw new TypeError('Expected Point')
  let q = ecurve.Point.decodeFrom(secp256k1, p)
  return q.getEncoded(compressed)
}

function pointDerive (d, compressed) {
  return secp256k1.G.multiply(d).getEncoded(compressed)
}

function privateAdd (d, tweak) {
  if (!isPrivate(d)) throw new TypeError('Expected Private')
  if (!isPrivate(tweak)) throw new TypeError('Expected Tweak')
  let dd = bigi.fromBuffer(d)
  let tt = bigi.fromBuffer(tweak)
  return dd.add(tt).mod(secp256k1.n)
}

function privateSub (d, tweak) {
  if (!isPrivate(d)) throw new TypeError('Expected Private')
  if (!isPrivate(tweak)) throw new TypeError('Expected Tweak')
  let dd = bigi.fromBuffer(d)
  let tt = bigi.fromBuffer(tweak)
  return dd.subtract(tt).mod(secp256k1.n)
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
  if (!isUInt256(hash)) throw new TypeError('Expected Hash')
  if (!isPrivate(x)) throw new TypeError('Expected Private')

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

  return { r, s }
}

function verify (hash, p, signature) {
  if (!isUInt256(hash)) throw new TypeError('Expected Hash')
  if (!isPoint(p)) throw new TypeError('Expected Private')
  if (!isSignature(signature)) throw new TypeError('Expected Signature')

  let Q = ecurve.Point.decodeFrom(secp256k1, p)
  let n = secp256k1.n
  let G = secp256k1.G

  let r = signature.r
  let s = signature.s

  // 1.4.1 Enforce r and s are both integers in the interval [1, n − 1]
  if (r.signum() <= 0 || r.compareTo(n) >= 0) return false
  if (s.signum() <= 0 || s.compareTo(n) >= 0) return false

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
  isPrivate,
  pointAdd,
  pointAddScalar,
  pointCompress,
  pointDerive,
  privateAdd,
  privateSub,
  sign,
  verify
}
