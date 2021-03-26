// eslint-disable-next-line @typescript-eslint/no-var-requires
const { exec } = require("child_process");

// eslint-disable-next-line @typescript-eslint/no-var-requires
const addon = require("./lib.node/addon.js");
if (addon.default === null) {
  const cmd = "cargo build --package secp256k1-node --release";
  exec(cmd, (error, _stdout, stderr) => {
    if (error !== null) {
      process.stdout.write(`Failed to build tiny-secp256k1 addon:\n${stderr}`);
    }
  });
}
