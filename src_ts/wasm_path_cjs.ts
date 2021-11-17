import * as nodePath from "path";

export function path(wasmFilename: string): string {
  // Since we know this file will only be used by cjs
  // and we know that wasm file will always be in the parent dir
  // We can translate to the parent directory without problem
  const pathname = nodePath.join(__dirname, "..", wasmFilename);
  return pathname;
}
