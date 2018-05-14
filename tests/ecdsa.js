let ecurve = require('../ecurve')
//  let elliptic = require('elliptic') // for reference
let native = require('bindings')('secp256k1')
let tape = require('tape')

let fecdsa = require('./fixtures/ecdsa.json')

function corrupt (x) {
  function randomUInt8 () {
    return Math.floor(Math.random() * 0xff)
  }

  x = Buffer.from(x)
  let mask = 1 << (randomUInt8() % 8)
  x[randomUInt8() % 32] ^= mask
  return x
}

function test (binding) {
  tape('sign', (t) => {
    fecdsa.valid.forEach((f) => {
      let d = Buffer.from(f.d, 'hex')
      let m = Buffer.from(f.m, 'hex')
      let expected = Buffer.from(f.signature, 'hex')

      t.same(binding.sign(m, d), expected, `sign(${f.m}, ...) == ${f.signature}`)
    })

    fecdsa.invalid.sign.forEach((f) => {
      let d = Buffer.from(f.d, 'hex')
      let m = Buffer.from(f.m, 'hex')

      t.throws(() => {
        binding.sign(m, d)
      }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
    })

    t.end()
  })

  tape('verify', (t) => {
    fecdsa.valid.forEach((f) => {
      let d = Buffer.from(f.d, 'hex')
      let Q = binding.pointFromScalar(d, true)
      let Qu = binding.pointFromScalar(d, false)
      let m = Buffer.from(f.m, 'hex')
      let signature = Buffer.from(f.signature, 'hex')
      let bad = corrupt(signature)

      t.equal(binding.verify(m, Q, signature), true, `verify(${f.signature}) is OK`)
      t.equal(binding.verify(m, Q, bad), false, `verify(${bad.toString('hex')}) is rejected`)
      t.equal(binding.verify(m, Qu, signature), true, `verify(${f.signature}) is OK`)
      t.equal(binding.verify(m, Qu, bad), false, `verify(${bad.toString('hex')}) is rejected`)
    })

    fecdsa.invalid.verify.forEach((f) => {
      let Q = Buffer.from(f.Q, 'hex')
      let m = Buffer.from(f.m, 'hex')
      let signature = Buffer.from(f.signature, 'hex')

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

test(ecurve)
test(native)
