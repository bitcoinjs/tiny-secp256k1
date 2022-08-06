## Reminder

Before you build the examples, you must build the tiny-secp256k1 project first.
Go to project root folder, run the following commands:
```
make build-wasm
npm ci
make build-js
```
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
npm run build
npm start
```

and open [http://localhost:8080/](http://localhost:8080/).
