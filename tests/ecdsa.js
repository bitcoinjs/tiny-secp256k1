const tape = require('tape')
const fecdsa = require('./fixtures/ecdsa.json')

const buf1 = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
const buf2 = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex')
const buf3 = Buffer.from('6e723d3fd94ed5d2b6bdd4f123364b0f3ca52af829988a63f8afe91d29db1c33', 'hex')
const buf4 = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')
const buf5 = Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex')

function corrupt (x) {
  function randomUInt8 () {
    return Math.floor(Math.random() * 0xff)
  }

  x = Buffer.from(x)
  const mask = 1 << (randomUInt8() % 8)
  x[randomUInt8() % 32] ^= mask
  return x
}

function test (binding) {
  tape('sign', (t) => {
    fecdsa.valid.forEach((f) => {
      const d = Buffer.from(f.d, 'hex')
      const m = Buffer.from(f.m, 'hex')
      const expected = Buffer.from(f.signature, 'hex')

      t.same(binding.sign(m, d), expected, `sign(${f.m}, ...) == ${f.signature}`)
    })

    fecdsa.extraEntropy.forEach((f) => {
      const d = Buffer.from(f.d, 'hex')
      const m = Buffer.from(f.m, 'hex')
      const expectedSig = Buffer.from(f.signature, 'hex')
      const expectedExtraEntropy0 = Buffer.from(f.extraEntropy0, 'hex')
      const expectedExtraEntropy1 = Buffer.from(f.extraEntropy1, 'hex')
      const expectedExtraEntropyRand = Buffer.from(f.extraEntropyRand, 'hex')
      const expectedExtraEntropyN = Buffer.from(f.extraEntropyN, 'hex')
      const expectedExtraEntropyMax = Buffer.from(f.extraEntropyMax, 'hex')

      const sig = binding.sign(m, d)

      const extraEntropyUndefined = binding.signWithEntropy(m, d, undefined)
      const extraEntropy0 = binding.signWithEntropy(m, d, buf1)
      const extraEntropy1 = binding.signWithEntropy(m, d, buf2)
      const extraEntropyRand = binding.signWithEntropy(m, d, buf3)
      const extraEntropyN = binding.signWithEntropy(m, d, buf4)
      const extraEntropyMax = binding.signWithEntropy(m, d, buf5)

      t.same(sig, expectedSig, `sign(${f.m}, ...) == ${f.signature}`)
      t.same(extraEntropyUndefined, expectedSig, `sign(${f.m}, ..., undefined) == ${f.signature}`)
      t.same(extraEntropy0, expectedExtraEntropy0, `sign(${f.m}, ..., 0) == ${f.signature}`)
      t.same(extraEntropy1, expectedExtraEntropy1, `sign(${f.m}, ..., 1) == ${f.signature}`)
      t.same(extraEntropyRand, expectedExtraEntropyRand, `sign(${f.m}, ..., rand) == ${f.signature}`)
      t.same(extraEntropyN, expectedExtraEntropyN, `sign(${f.m}, ..., n) == ${f.signature}`)
      t.same(extraEntropyMax, expectedExtraEntropyMax, `sign(${f.m}, ..., max256) == ${f.signature}`)
    })

    fecdsa.invalid.sign.forEach((f) => {
      const d = Buffer.from(f.d, 'hex')
      const m = Buffer.from(f.m, 'hex')

      t.throws(() => {
        binding.sign(m, d)
      }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
    })

    t.end()
  })

  tape('verify', (t) => {
    fecdsa.valid.forEach((f) => {
      const d = Buffer.from(f.d, 'hex')
      const Q = binding.pointFromScalar(d, true)
      const Qu = binding.pointFromScalar(d, false)
      const m = Buffer.from(f.m, 'hex')
      const signature = Buffer.from(f.signature, 'hex')
      const bad = corrupt(signature)

      t.equal(binding.verify(m, Q, signature), true, `verify(${f.signature}) is OK`)
      t.equal(binding.verify(m, Q, bad), false, `verify(${bad.toString('hex')}) is rejected`)
      t.equal(binding.verify(m, Qu, signature), true, `verify(${f.signature}) is OK`)
      t.equal(binding.verify(m, Qu, bad), false, `verify(${bad.toString('hex')}) is rejected`)
    })

    fecdsa.invalid.verify.forEach((f) => {
      const Q = Buffer.from(f.Q, 'hex')
      const m = Buffer.from(f.m, 'hex')
      const signature = Buffer.from(f.signature, 'hex')

      if (f.exception) {
        t.throws(() => {
          binding.verify(m, Q, signature)
        }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
      } else {
        t.equal(binding.verify(m, Q, signature), false, `verify(${f.signature}) is rejected`)
      }
    })

    t.end()
  })
}

module.exports = test
