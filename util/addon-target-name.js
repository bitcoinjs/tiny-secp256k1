function getName() {
  switch (process.platform) {
    case "darwin":
      return "libsecp256k1_node.dylib";
    case "win32":
      return "secp256k1_node.dll";
    case "linux":
    case "freebsd":
    case "openbsd":
    case "android":
    case "sunos":
      return "libsecp256k1_node.so";
    default:
      throw new Error(`Unknow platform: ${process.platform}`);
  }
}

process.stdout.write(getName());
