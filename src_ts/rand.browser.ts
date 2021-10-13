export function generateInt32(): number {
  const array = new Uint8Array(4);
  window.crypto.getRandomValues(array);
  return (
    (array[0] << (3 * 8)) +
    (array[1] << (2 * 8)) +
    (array[2] << (1 * 8)) +
    array[3]
  );
}
