const { randomBytes } = require("crypto");

const ERROR_BAD_PRIVATE = 0;
const ERROR_BAD_POINT = 1;
const ERROR_BAD_TWEAK = 2;
const ERROR_BAD_HASH = 3;
const ERROR_BAD_SIGNATURE = 4;
const ERROR_BAD_EXTRA_DATA = 5;

const ERRORS_MESSAGES = {
  [ERROR_BAD_PRIVATE]: "Expected Private",
  [ERROR_BAD_POINT]: "Expected Point",
  [ERROR_BAD_TWEAK]: "Expected Tweak",
  [ERROR_BAD_HASH]: "Expected Hash",
  [ERROR_BAD_SIGNATURE]: "Expected Signature",
  [ERROR_BAD_EXTRA_DATA]: "Expected Extra Data (32 bytes)",
};

function generateInt32() {
  return randomBytes(4).readInt32BE(0);
}

function throwError(errcode) {
  const message = ERRORS_MESSAGES[errcode] || `Unknow error code: ${errcode}`;
  throw new TypeError(message);
}

module.exports = {
  ERROR_BAD_PRIVATE,
  ERROR_BAD_POINT,
  ERROR_BAD_TWEAK,
  ERROR_BAD_HASH,
  ERROR_BAD_SIGNATURE,
  ERROR_BAD_EXTRA_DATA,

  generateInt32,
  throwError,
};
