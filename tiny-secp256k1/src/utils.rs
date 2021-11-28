use super::{
    consts::{PUBLIC_KEY_COMPRESSED_SIZE, PUBLIC_KEY_UNCOMPRESSED_SIZE},
    error::Error,
    types::{InvalidInputResult, PubkeySlice},
};

use secp256k1_sys::{
    secp256k1_context_no_precomp, secp256k1_ec_pubkey_parse, secp256k1_ec_pubkey_serialize,
    secp256k1_keypair_create, secp256k1_xonly_pubkey_from_pubkey, secp256k1_xonly_pubkey_parse,
    secp256k1_xonly_pubkey_serialize, Context, KeyPair, PublicKey, XOnlyPublicKey,
    SECP256K1_SER_COMPRESSED, SECP256K1_SER_UNCOMPRESSED,
};

#[cfg(feature = "rand")]
use super::set_context;
#[cfg(feature = "rand")]
use rand::{self, RngCore};

#[allow(clippy::large_stack_arrays)]
pub(crate) static CONTEXT_BUFFER: [u8; 1_114_320] = [0; 1_114_320];
pub(crate) static mut CONTEXT: *const Context = core::ptr::null();
pub(crate) static mut CONTEXT_SET: bool = false;

pub(crate) fn get_context() -> *const Context {
    unsafe {
        if CONTEXT_SET {
            CONTEXT
        } else {
            #[cfg(feature = "rand")]
            {
                let mut seed = [0_u8; 32];
                rand::thread_rng().fill_bytes(&mut seed);
                set_context(seed)
            }
            #[cfg(not(feature = "rand"))]
            panic!("No context");
        }
    }
}

pub(crate) fn assume_compression(compressed: Option<bool>, p: Option<&PubkeySlice>) -> usize {
    compressed.map_or_else(
        || p.map_or(PUBLIC_KEY_COMPRESSED_SIZE, |v| v.1),
        |v| {
            if v {
                PUBLIC_KEY_COMPRESSED_SIZE
            } else {
                PUBLIC_KEY_UNCOMPRESSED_SIZE
            }
        },
    )
}

pub(crate) unsafe fn create_keypair(input: *const u8) -> InvalidInputResult<KeyPair> {
    let mut kp = KeyPair::new();
    if secp256k1_keypair_create(get_context(), &mut kp, input) == 1 {
        Ok(kp)
    } else {
        Err(Error::BadPrivate)
    }
}

pub(crate) unsafe fn x_only_pubkey_from_pubkey(
    input: *const u8,
    inputlen: usize,
) -> InvalidInputResult<(XOnlyPublicKey, i32)> {
    let mut xonly_pk = XOnlyPublicKey::new();
    let mut parity: i32 = 0;
    let pubkey = pubkey_parse(input, inputlen)?;
    x_only_pubkey_from_pubkey_struct(&mut xonly_pk, &mut parity, &pubkey);
    Ok((xonly_pk, parity))
}

pub(crate) unsafe fn x_only_pubkey_from_pubkey_struct(
    xonly_pk: &mut XOnlyPublicKey,
    parity: &mut i32,
    pubkey: &PublicKey,
) {
    assert_eq!(
        secp256k1_xonly_pubkey_from_pubkey(get_context(), xonly_pk, parity, pubkey),
        1
    );
}

pub(crate) unsafe fn pubkey_parse(
    input: *const u8,
    inputlen: usize,
) -> InvalidInputResult<PublicKey> {
    let mut pk = PublicKey::new();
    if secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &mut pk, input, inputlen) == 1 {
        Ok(pk)
    } else {
        Err(Error::BadPoint)
    }
}

pub(crate) unsafe fn x_only_pubkey_parse(input: *const u8) -> InvalidInputResult<XOnlyPublicKey> {
    let mut pk = XOnlyPublicKey::new();
    if secp256k1_xonly_pubkey_parse(secp256k1_context_no_precomp, &mut pk, input) == 1 {
        Ok(pk)
    } else {
        Err(Error::BadPoint)
    }
}

pub(crate) unsafe fn pubkey_serialize(pk: &PublicKey, output: *mut u8, mut outputlen: usize) {
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
            pk.as_ptr().cast::<PublicKey>(),
            flags,
        ),
        1
    );
}

pub(crate) unsafe fn x_only_pubkey_serialize(pk: &XOnlyPublicKey, output: *mut u8) {
    assert_eq!(
        secp256k1_xonly_pubkey_serialize(
            secp256k1_context_no_precomp,
            output,
            pk.as_ptr().cast::<XOnlyPublicKey>(),
        ),
        1
    );
}
