# tiny-secp256k1

[![NPM](https://img.shields.io/npm/v/tiny-secp256k1.svg)](https://www.npmjs.org/package/tiny-secp256k1)

This library is under development, and, like the [secp256k1](https://github.com/bitcoin-core/secp256k1) C library (through [secp256k1-sys](https://github.com/rust-bitcoin/rust-secp256k1/) Rust crate) it depends on, this is a research effort to determine an optimal API for end-users of the bitcoinjs ecosystem.

## Installation

### npm

```bash
npm install tiny-secp256k1
```

### yarn

```bash
yarn add tiny-secp256k1
```

## WebAssembly and Node.js version

Previous version of `tiny-secp256k1` implement [C++ addon](https://nodejs.org/api/addons.html) through [NAN (Native Abstractions for Node.js)](https://github.com/nodejs/nan) and [elliptic](https://github.com/indutny/elliptic) as fallback when addon can not be built or in browser-like environement.

Current version use Rust crate (which use C library) compiled to [WebAssembly](https://developer.mozilla.org/en-US/docs/WebAssembly). With Wasm same code executed in any environment. Wasm is faster than `elliptic` but slower than node bindings ([results in PR](https://github.com/bitcoinjs/tiny-secp256k1/pull/53#issuecomment-801844450) or you can run own benchmark in `benches` directory).

Tools like webpack, environments like React Native, and a large part of the JavaScript/TypeScript ecosystem has support for WASM based libraries. However, it usually involves special config settings which might be difficult to figure out. We have examples in the examples folder that uses webpack to create a demo website.

However, there are also **alternative implementations** of the interface of this library.

## Alternatives

1. [`@bitcoinjs-lib/tiny-secp256k1-asmjs`](https://www.npmjs.com/package/@bitcoin-js/tiny-secp256k1-asmjs) - This library uses wasm2js to convert this library into pure JS. It is about 10x ~ 20x slower than WASM and 3x ~ 10x slower than our old v1 JS implementation.
2. [`@bitcoinerlab/secp256k1`](https://www.npmjs.com/package/@bitcoinerlab/secp256k1) - This library uses noble/secp256k1, and therefore it uses JS native `BigInt`. If you can support `BigInt` it is much faster than ASM.JS, however, this is not maintained by this library's maintainers, so there's no guarantee that they will keep up with any interface changes in the future. Please check before using. It is about 1.5x ~ 5x slower than WASM.

## Building

For building locally you need C/C++ toolchain, Rust version >=1.50.0 and `wasm-opt` from [binaryen](https://github.com/WebAssembly/binaryen).

[rustup](https://rustup.rs/) is a recommended way to install `Rust`. You also will need `wasm32-unknown-unknown` target.

```
rustup toolchain install stable --target wasm32-unknown-unknown --component clippy --component rustfmt
```

After installing development dependencies with `npm` you can build Wasm:

```
make build-wasm
```

or run tests:

```
make test
```

Alternative way is to use [Docker](https://www.docker.com/):

```
% docker build -t tiny-secp256k1 .
% docker run -it --rm -v `pwd`:/tiny-secp256k1 -w /tiny-secp256k1 tiny-secp256k1
# make build
```

## Examples

`tiny-secp256k1` includes two examples. First is [simple script for Node.js](examples/random-in-node) which generate random data and print arguments and methods results. Second is [React app](examples/react-app).

React app is builded in GitHub Actions on each commit to master branch and uploaded to [gh-pages](https://github.com/bitcoinjs/tiny-secp256k1/tree/gh-pages) branch, which is always available online: https://bitcoinjs.github.io/tiny-secp256k1/

## Documentation

### isPoint (A)

```haskell
isPoint :: Buffer -> Bool
```

Returns `false` if

- `A` is not encoded with a sequence tag of `0x02`, `0x03` or `0x04`
- `A.x` is not in `[1...p - 1]`
- `A.y` is not in `[1...p - 1]`

### isPointCompressed (A)

```haskell
isPointCompressed :: Buffer -> Bool
```

Returns `false` if the pubkey is **not** compressed.

### isXOnlyPoint (A)

```haskell
isXOnlyPoint :: Buffer -> Bool
```

Returns `false` if the pubkey is **not** an xOnlyPubkey.

### isPrivate (d)

```haskell
isPrivate :: Buffer -> Bool
```

Returns `false` if

- `d` is not 256-bit, or
- `d` is not in `[1..order - 1]`

### pointAdd (A, B[, compressed])

```haskell
pointAdd :: Buffer -> Buffer [-> Bool] -> Maybe Buffer
```

Returns `null` if result is at infinity.

##### Throws:

- `Expected Point` if `!isPoint(A)`
- `Expected Point` if `!isPoint(B)`

### pointAddScalar (A, tweak[, compressed])

```haskell
pointAddScalar :: Buffer -> Buffer [-> Bool] -> Maybe Buffer
```

Returns `null` if result is at infinity.

##### Throws:

- `Expected Point` if `!isPoint(A)`
- `Expected Tweak` if `tweak` is not in `[0...order - 1]`

### pointCompress (A, compressed)

```haskell
pointCompress :: Buffer -> Bool -> Buffer
```

##### Throws:

- `Expected Point` if `!isPoint(A)`

### pointFromScalar (d[, compressed])

```haskell
pointFromScalar :: Buffer [-> Bool] -> Maybe Buffer
```

Returns `null` if result is at infinity.

##### Throws:

- `Expected Private` if `!isPrivate(d)`

### xOnlyPointFromScalar (d)

```haskell
xOnlyPointFromScalar :: Buffer -> Buffer
```

Returns the xOnlyPubkey for a given private key

##### Throws:

- `Expected Private` if `!isPrivate(d)`

### xOnlyPointFromPoint (p)

```haskell
xOnlyPointFromPoint :: Buffer -> Buffer
```

Returns the xOnlyPubkey for a given DER public key

##### Throws:

- `Expected Point` if `!isPoint(p)`

### pointMultiply (A, tweak[, compressed])

```haskell
pointMultiply :: Buffer -> Buffer [-> Bool] -> Maybe Buffer
```

Returns `null` if result is at infinity.

##### Throws:

- `Expected Point` if `!isPoint(A)`
- `Expected Tweak` if `tweak` is not in `[0...order - 1]`

### privateAdd (d, tweak)

```haskell
privateAdd :: Buffer -> Buffer -> Maybe Buffer
```

Returns `null` if result is equal to `0`.

##### Throws:

- `Expected Private` if `!isPrivate(d)`
- `Expected Tweak` if `tweak` is not in `[0...order - 1]`

### privateSub (d, tweak)

```haskell
privateSub :: Buffer -> Buffer -> Maybe Buffer
```

Returns `null` if result is equal to `0`.

##### Throws:

- `Expected Private` if `!isPrivate(d)`
- `Expected Tweak` if `tweak` is not in `[0...order - 1]`

### privateNegate (d)

```haskell
privateNegate :: Buffer -> Buffer
```

Returns the negation of d on the order n (`n - d`)

##### Throws:

- `Expected Private` if `!isPrivate(d)`

### xOnlyPointAddTweak (p, tweak)

```haskell
xOnlyPointAddTweak :: Buffer -> Buffer -> { parity: 1 | 0; xOnlyPubkey: Buffer; }
```

Returns the tweaked xOnlyPubkey along with the parity bit (number type of 1|0)

##### Throws:

- `Expected Point` if `!isXOnlyPoint(p)`
- `Expected Tweak` if `!isXOnlyPoint(tweak)`

### xOnlyPointAddTweakCheck (p1, p2, tweak[, tweakParity])

```haskell
xOnlyPointAddTweakCheck :: Buffer -> Buffer -> Buffer [-> 1 | 0] -> Bool
```

Checks the tweaked pubkey (p2) against the original pubkey (p1) and tweak.
This is slightly slower if you include tweakParity, tweakParity will make it
faster for aggregation later on.

##### Throws:

- `Expected Point` if `!isXOnlyPoint(p1)`
- `Expected Point` if `!isXOnlyPoint(p2)`
- `Expected Tweak` if `!isXOnlyPoint(tweak)`
- `Expected Parity` if `tweakParity is not 1 or 0`

### sign (h, d[, e])

```haskell
sign :: Buffer -> Buffer [-> Buffer] -> Buffer
```

Returns normalized signatures, each of (r, s) values are guaranteed to less than `order / 2`.
Uses RFC6979.
Adds `e` as Added Entropy to the deterministic k generation.

##### Throws:

- `Expected Private` if `!isPrivate(d)`
- `Expected Scalar` if `h` is not 256-bit
- `Expected Extra Data (32 bytes)` if `e` is not 256-bit

### signRecoverable (h, d[, e])

```haskell
signRecoverable :: Buffer -> Buffer [-> Buffer] -> { recoveryId: 0 | 1 | 2 | 3; signature: Buffer; }
```

Returns normalized signatures and recovery Id, each of (r, s) values are guaranteed to less than `order / 2`.
Uses RFC6979.
Adds `e` as Added Entropy to the deterministic k generation.

##### Throws:

- `Expected Private` if `!isPrivate(d)`
- `Expected Scalar` if `h` is not 256-bit
- `Expected Extra Data (32 bytes)` if `e` is not 256-bit

### signSchnorr (h, d[, e])

```haskell
signSchnorr :: Buffer -> Buffer [-> Buffer] -> Buffer
```

Returns normalized schnorr signature.
Uses BIP340 nonce generation.
Adds `e` as Added Entropy.

##### Throws:

- `Expected Private` if `!isPrivate(d)`
- `Expected Scalar` if `h` is not 256-bit
- `Expected Extra Data (32 bytes)` if `e` is not 256-bit

### verify (h, Q, signature[, strict = false])

```haskell
verify :: Buffer -> Buffer -> Buffer [-> Bool] -> Bool
```

Returns `false` if any of (r, s) values are equal to `0`, or if the signature is rejected.

If `strict` is `true`, valid signatures with any of (r, s) values greater than `order / 2` are rejected.

##### Throws:

- `Expected Point` if `!isPoint(Q)`
- `Expected Signature` if `signature` has any (r, s) values not in range `[0...order - 1]`
- `Expected Scalar` if `h` is not 256-bit

### recover (h, signature, recoveryId[, compressed = false])

```haskell
verify :: Buffer -> Buffer -> Number [-> Bool] -> Maybe Buffer
```

Returns the ECDSA public key from a signature if it can be recovered, `null` otherwise.


##### Throws:

- `Expected Signature` if `signature` has any (r, s) values not in range `(0...order - 1]`
- `Bad Recovery Id` if `recid & 2 !== 0`  and `signature` has any r value not in range `(0...P - N - 1]`
- `Expected Hash` if `h` is not 256-bit


### verifySchnorr (h, Q, signature)

```haskell
verifySchnorr :: Buffer -> Buffer -> Buffer -> Bool
```

Returns `false` if any of (r, s) values are equal to `0`, or if the signature is rejected.

##### Throws:

- `Expected Point` if `!isPoint(Q)`
- `Expected Signature` if `signature` has any (r, s) values not in range `[0...order - 1]`
- `Expected Scalar` if `h` is not 256-bit

## Credit

This library uses the native library [secp256k1](https://github.com/bitcoin-core/secp256k1) by the bitcoin-core developers through Rust crate [secp256k1-sys](https://crates.io/crates/secp256k1-sys), including derivatives of its tests and test vectors.

# LICENSE [MIT](LICENSE)
