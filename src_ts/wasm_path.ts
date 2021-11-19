import { URL, fileURLToPath } from "url";

export function path(wasmFilename: string): string {
  const url = new URL(wasmFilename, import.meta.url);
  return fileURLToPath(url);
}
