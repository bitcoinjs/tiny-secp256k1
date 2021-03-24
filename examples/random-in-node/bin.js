import * as secp256k1 from "../../lib/index.js";
import { generate } from "./index.js";

const toHex = (v) =>
  v instanceof Uint8Array ? Buffer.from(v).toString("hex") : v;

const lineDash = new Array(80).fill("-").join("");
const lineEq = new Array(80).fill("=").join("");
function print(items) {
  let firstPrint = true;
  for (const item of items) {
    if (firstPrint) {
      console.log(lineEq);
      firstPrint = false;
    }
    console.log(`Method: ${item.name}`);
    console.log(lineDash);
    for (let i = 0; i < item.args.length; ++i) {
      console.log(`Arg${(i + 1).toString()}: ${toHex(item.args[i])}`);
    }
    console.log(`Result: ${toHex(secp256k1[item.name](...item.args))}`);
    console.log(lineEq);
  }
}

const data = generate();
print([
  { name: "isPoint", args: [data.pubkey_uncompressed] },
  { name: "isPointCompressed", args: [data.pubkey] },
  { name: "isPrivate", args: [data.seckey] },
  { name: "pointAdd", args: [data.pubkey, data.pubkey2] },
  { name: "pointAddScalar", args: [data.pubkey, data.tweak] },
  { name: "pointCompress", args: [data.pubkey_uncompressed, true] },
  { name: "pointFromScalar", args: [data.seckey] },
  { name: "pointMultiply", args: [data.pubkey, data.tweak] },
  { name: "privateAdd", args: [data.seckey, data.tweak] },
  { name: "privateSub", args: [data.seckey, data.tweak] },
  { name: "sign", args: [data.hash, data.seckey] },
  { name: "signWithEntropy", args: [data.hash, data.seckey, data.entropy] },
  {
    name: "verify",
    args: [data.hash, data.pubkey, secp256k1.sign(data.hash, data.seckey)],
  },
]);
