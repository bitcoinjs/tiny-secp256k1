import { URL } from "url";

export function path(wasmFilename: string): string {
  const { pathname } = new URL(wasmFilename, import.meta.url);
  return pathname;
}
