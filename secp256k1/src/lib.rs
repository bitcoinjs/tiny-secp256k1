#![allow(clippy::missing_safety_doc)]
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![feature(core_intrinsics)]

#[cfg(not(any(test, feature = "std")))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::intrinsics::abort()
}

pub use secp256k1_sys::{
    secp256k1_context_no_precomp, secp256k1_context_preallocated_create,
    secp256k1_context_preallocated_size, secp256k1_context_randomize, secp256k1_ec_pubkey_combine,
    secp256k1_ec_pubkey_create, secp256k1_ec_pubkey_parse, secp256k1_ec_pubkey_serialize,
    secp256k1_ec_pubkey_tweak_add, secp256k1_ec_pubkey_tweak_mul, secp256k1_ec_seckey_negate,
    secp256k1_ec_seckey_tweak_add, secp256k1_ecdsa_sign, secp256k1_ecdsa_signature_normalize,
    secp256k1_ecdsa_signature_parse_compact, secp256k1_ecdsa_signature_serialize_compact,
    secp256k1_ecdsa_verify, secp256k1_nonce_function_rfc6979, types::c_void, Context, PublicKey,
    Signature, SECP256K1_START_SIGN, SECP256K1_START_VERIFY,
};
use secp256k1_sys::{SECP256K1_SER_COMPRESSED, SECP256K1_SER_UNCOMPRESSED};

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;
pub const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
pub const TWEAK_SIZE: usize = 32;
pub const HASH_SIZE: usize = 32;
pub const EXTRA_DATA_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

// pub const ERROR_BAD_PRIVATE: usize = 0;
pub const ERROR_BAD_POINT: usize = 1;
// pub const ERROR_BAD_TWEAK: usize = 2;
// pub const ERROR_BAD_HASH: usize = 3;
pub const ERROR_BAD_SIGNATURE: usize = 4;
// pub const ERROR_BAD_EXTRA_DATA: usize = 5;

type InvalidInputResult<T> = Result<T, usize>;

pub unsafe fn pubkey_parse(input: *const u8, inputlen: usize) -> InvalidInputResult<PublicKey> {
    let mut pk = PublicKey::new();
    if secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &mut pk, input, inputlen) == 1 {
        Ok(pk)
    } else {
        Err(ERROR_BAD_POINT)
    }
}

pub unsafe fn pubkey_serialize(pk: &PublicKey, output: *mut u8, mut outputlen: usize) {
    let flags = if outputlen == PUBLIC_KEY_COMPRESSED_SIZE {
        SECP256K1_SER_COMPRESSED
    } else {
        SECP256K1_SER_UNCOMPRESSED
    };
    assert_eq!(
        secp256k1_ec_pubkey_serialize(
            secp256k1_context_no_precomp,
            output,
            &mut outputlen,
            pk.as_ptr() as *const PublicKey,
            flags,
        ),
        1
    );
}
