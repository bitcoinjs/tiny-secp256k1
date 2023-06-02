export function randomBytes(byteCount) {
  const res = new Uint8Array(byteCount);
  window.crypto.getRandomValues(res);
  return res;
}
