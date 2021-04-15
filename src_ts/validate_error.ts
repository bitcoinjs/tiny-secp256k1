export const ERROR_BAD_PRIVATE = 0;
export const ERROR_BAD_POINT = 1;
export const ERROR_BAD_TWEAK = 2;
export const ERROR_BAD_HASH = 3;
export const ERROR_BAD_SIGNATURE = 4;
export const ERROR_BAD_EXTRA_DATA = 5;

const ERRORS_MESSAGES = {
  [ERROR_BAD_PRIVATE.toString()]: "Expected Private",
  [ERROR_BAD_POINT.toString()]: "Expected Point",
  [ERROR_BAD_TWEAK.toString()]: "Expected Tweak",
  [ERROR_BAD_HASH.toString()]: "Expected Hash",
  [ERROR_BAD_SIGNATURE.toString()]: "Expected Signature",
  [ERROR_BAD_EXTRA_DATA.toString()]: "Expected Extra Data (32 bytes)",
};

export function throwError(errcode: number): never {
  const message =
    ERRORS_MESSAGES[errcode.toString()] || `Unknow error code: ${errcode}`;
  throw new TypeError(message);
}
