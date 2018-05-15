let ecurve = require('../ecurve')
//  let elliptic = require('elliptic') // for reference
let native = require('bindings')('secp256k1')
let tape = require('tape')
let fprivates = require('./fixtures/privates.json')

function test (binding) {
  tape('isPrivate', (t) => {
    fprivates.valid.isPrivate.forEach((f) => {
      let d = Buffer.from(f.d, 'hex')

      t.equal(binding.isPrivate(d), f.expected, `${f.d} is ${f.expected ? 'OK' : 'rejected'}`)
    })

    t.end()
  })

  tape('privateAdd', (t) => {
    fprivates.valid.privateAdd.forEach((f) => {
      let d = Buffer.from(f.d, 'hex')
      let tweak = Buffer.from(f.tweak, 'hex')
      let expected = f.expected ? Buffer.from(f.expected, 'hex') : null
      let description = `${f.d} + ${f.tweak} = ${f.expected ? f.expected : null}`
      if (f.description) description += ` (${f.description})`

      t.same(binding.privateAdd(d, tweak), expected, description)
    })

    fprivates.invalid.privateAdd.forEach((f) => {
      let d = Buffer.from(f.d, 'hex')
      let tweak = Buffer.from(f.tweak, 'hex')

      t.throws(() => {
        binding.privateAdd(d, tweak)
      }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
    })

    t.end()
  })

  tape('privateSub', (t) => {
    fprivates.valid.privateSub.forEach((f) => {
      let d = Buffer.from(f.d, 'hex')
      let tweak = Buffer.from(f.tweak, 'hex')
      let expected = f.expected ? Buffer.from(f.expected, 'hex') : null
      let description = `${f.d} - ${f.tweak} = ${f.expected ? f.expected : null}`
      if (f.description) description += ` (${f.description})`

      t.same(binding.privateSub(d, tweak), expected, description)
    })

    fprivates.invalid.privateSub.forEach((f) => {
      let d = Buffer.from(f.d, 'hex')
      let tweak = Buffer.from(f.tweak, 'hex')

      t.throws(() => {
        binding.privateSub(d, tweak)
      }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
    })

    t.end()
  })
}

test(ecurve)
test(native)
