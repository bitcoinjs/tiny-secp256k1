import { randomBytes as rand } from "crypto";

export function randomBytes(byteCount) {
  return Uint8Array.from(rand(byteCount));
}
