function fromHex(data) {
  return new Uint8Array(Buffer.from(data, "hex"));
}

function toHex(data) {
  return Buffer.from(data).toString("hex");
}

module.exports = {
  fromHex,
  toHex,
};
