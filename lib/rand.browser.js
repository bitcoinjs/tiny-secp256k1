export function generateInt32() {
  const array = new Uint8Array(4);
  window.crypto.getRandomValues(array);
  return (array[0] << 3) + (array[1] << 2) + (array[2] << 1) + array[1];
}
