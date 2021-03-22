import { join } from "path";
import createApi from "./api.js";
import { Secp256k1InternalApi, Secp256k1Api } from "./api.js";
import { generateSeed } from "./rand.js";
import { throwError } from "./validate_error.js";

function getLibExt(): string {
  switch (process.platform) {
    case "darwin":
      return "dylib";
    case "win32":
      return "dll";
    case "linux":
    case "freebsd":
    case "openbsd":
    case "android":
    case "sunos":
      return "so";
    default:
      return "¯\\_(ツ)_/¯";
  }
}

function getPrebuildLibLocation(): string {
  const name = `secp256k1-${process.arch}-${process.platform}.${getLibExt()}`;
  return new URL(name, import.meta.url).pathname;
}

function getLocalBuildLibLocation(mode: string): string {
  const path = join("..", "target", mode, "libsecp256k1_node.so");
  return new URL(path, import.meta.url).pathname;
}

function dlopen(location: string): Secp256k1InternalApi {
  const module = { exports: { throwError, generateSeed } };
  // Suppress TS2339: Property 'dlopen' does not exist on type 'Process'.
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  process.dlopen(module, location);
  return (module.exports as unknown) as Secp256k1InternalApi;
}

export function loadAddon(location: string): Secp256k1Api | null {
  try {
    return createApi(dlopen(location));
  } catch (_error) {
    return null;
  }
}

export default loadAddon(getLocalBuildLibLocation("debug")) ||
  loadAddon(getLocalBuildLibLocation("release")) ||
  loadAddon(getPrebuildLibLocation());
