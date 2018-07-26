const tape = require('tape')
const fecdsa = require('./fixtures/ecdsa.json')

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
