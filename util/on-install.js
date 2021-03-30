import { exec } from "child_process";
import addon from "./lib/addon.js";

if (addon === null) {
  const cmd = "cargo build --package secp256k1-node --release";
  exec(cmd, (error, _stdout, stderr) => {
    if (error !== null) {
      process.stdout.write(`Failed to build tiny-secp256k1 addon:\n${stderr}`);
    }
  });
}
