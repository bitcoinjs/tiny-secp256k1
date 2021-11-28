
## random-in-node

Generate data and demonstrate arguments/result for different methods of `tiny-secp256k1`.

```
npm install
npm start
```

## react-app

[React](https://reactjs.org/) application with inputs for testing `tiny-secp256k1` methods.

```
npm install
npm start
```

and open [http://localhost:8080/](http://localhost:8080/).

## simple-timing-test

Run this command multiple times to confirm there is no difference in processing time with EC point multiplication.

Variance is usually under 0.5%, but it fluctuates. For comparison, Native JS of v1 of this library has a 40% variance
between private key 2 and n - 1.

```
node ./run.js
```