const fs = require("fs");
const binaryen = require("binaryen");

const NOT_USED_FUNCTIONS = [
  "rustsecp256k1_v0_4_0_default_error_callback_fn",
  "rustsecp256k1_v0_4_0_default_illegal_callback_fn",
  "rustsecp256k1_v0_4_0_context_preallocated_clone_size",
  "rustsecp256k1_v0_4_0_context_preallocated_clone",
  "rustsecp256k1_v0_4_0_context_preallocated_destroy",
  "rustsecp256k1_v0_4_0_context_set_illegal_callback",
  "rustsecp256k1_v0_4_0_context_set_error_callback",
  "rustsecp256k1_v0_4_0_ecdsa_signature_parse_der",
  "rustsecp256k1_v0_4_0_ecdsa_signature_serialize_der",
  "rustsecp256k1_v0_4_0_ec_seckey_verify",
  "rustsecp256k1_v0_4_0_ec_privkey_negate",
  "rustsecp256k1_v0_4_0_ec_pubkey_negate",
  "rustsecp256k1_v0_4_0_ec_privkey_tweak_add",
  "rustsecp256k1_v0_4_0_ec_seckey_tweak_mul",
  "rustsecp256k1_v0_4_0_ec_privkey_tweak_mul",
];
const NOT_USED_GLOBALS = ["rustsecp256k1_v0_4_0_nonce_function_default"];

const NOT_EXPORTED_FUNCTIONS = [
  "rustsecp256k1_v0_4_0_context_preallocated_size",
  "rustsecp256k1_v0_4_0_context_preallocated_create",
  "rustsecp256k1_v0_4_0_context_randomize",
  "rustsecp256k1_v0_4_0_context_no_precomp",
  "rustsecp256k1_v0_4_0_ec_pubkey_parse",
  "rustsecp256k1_v0_4_0_ec_pubkey_combine",
  "rustsecp256k1_v0_4_0_ec_pubkey_serialize",
  "rustsecp256k1_v0_4_0_ec_pubkey_tweak_add",
  "rustsecp256k1_v0_4_0_ec_pubkey_create",
  "rustsecp256k1_v0_4_0_ec_pubkey_tweak_mul",
  "rustsecp256k1_v0_4_0_ec_seckey_tweak_add",
  "rustsecp256k1_v0_4_0_ec_seckey_negate",
  "rustsecp256k1_v0_4_0_nonce_function_rfc6979",
  "rustsecp256k1_v0_4_0_ecdsa_sign",
  "rustsecp256k1_v0_4_0_ecdsa_signature_serialize_compact",
  "rustsecp256k1_v0_4_0_ecdsa_signature_parse_compact",
  "rustsecp256k1_v0_4_0_ecdsa_signature_normalize",
  "rustsecp256k1_v0_4_0_ecdsa_verify",
];

function strip(input) {
  const module = binaryen.readBinary(input);

  for (const name of NOT_USED_FUNCTIONS) {
    module.removeFunction(name);
    module.removeExport(name);
  }
  for (const name of NOT_USED_GLOBALS) {
    module.removeGlobal(name);
    module.removeExport(name);
  }

  for (const name of NOT_EXPORTED_FUNCTIONS) {
    module.removeExport(name);
  }

  return module.emitBinary();
}

function main(location) {
  const input = fs.readFileSync(location);
  const output = strip(input);

  const change = input.length - output.length;
  console.log(`Size: ${input.length} -> ${output.length} (save ${change}+)`);

  fs.writeFileSync(location, output);
}

main(process.argv[2]);
