let ecurve = require('../ecurve')
//  let elliptic = require('elliptic') // for reference
//  let native = require('bindings')('secp256k1')
let tape = require('tape')

//  let fpoints = require('./fixtures/points.json')
let fprivates = require('./fixtures/privates.json')
//  let fecdsa = require('./fixtures/ecdsa.json')

function summary (x) {
  return x.slice(0, x.length / 4) + '...' + x.slice(x.length * (3 / 4))
}

fprivates.valid.isPrivate.forEach((f) => {
  let d = Buffer.from(f.d, 'hex')

  tape(`${summary(f.d)} is ${f.expected ? 'OK' : 'rejected'}`, (t) => {
    t.plan(1)
    t.equal(ecurve.isPrivate(d), f.expected)
  })
})

fprivates.valid.privateAdd.forEach((f) => {
  let d = Buffer.from(f.d, 'hex')
  let tweak = Buffer.from(f.tweak, 'hex')
  let expected = f.expected ? Buffer.from(f.expected, 'hex') : null
  let tdescription = `${summary(f.d)} + ${summary(f.tweak)} = ${f.expected ? summary(f.expected) : null}`

  tape(`${f.description ? f.description : ''} ` + tdescription, (t) => {
    t.plan(1)
    t.same(ecurve.privateAdd(d, tweak), expected)
  })
})

fprivates.invalid.privateAdd.forEach((f) => {
  let d = Buffer.from(f.d, 'hex')
  let tweak = Buffer.from(f.tweak, 'hex')

  tape(`${f.description} throws ${f.exception}`, (t) => {
    t.plan(1)
    t.throws(() => {
      ecurve.privateAdd(d, tweak)
    }, new RegExp(f.exception))
  })
})
