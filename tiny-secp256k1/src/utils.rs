use secp256k1_sys::{
    secp256k1_context_no_precomp, secp256k1_ec_pubkey_parse, secp256k1_ec_pubkey_serialize,
    secp256k1_keypair_create, secp256k1_xonly_pubkey_from_pubkey, secp256k1_xonly_pubkey_parse,
    secp256k1_xonly_pubkey_serialize, Context, KeyPair, PublicKey, XOnlyPublicKey,
    SECP256K1_SER_COMPRESSED, SECP256K1_SER_UNCOMPRESSED,
};

pub(crate) type InvalidInputResult<T> = Result<T, usize>;
pub(crate) const ZERO32: [u8; 32] = [0_u8; 32];

pub(crate) const PRIVATE_KEY_SIZE: usize = 32;
pub(crate) const PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;
pub(crate) const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
pub(crate) const X_ONLY_PUBLIC_KEY_SIZE: usize = 32;
pub(crate) const TWEAK_SIZE: usize = 32;
pub(crate) const HASH_SIZE: usize = 32;
pub(crate) const EXTRA_DATA_SIZE: usize = 32;
pub(crate) const SIGNATURE_SIZE: usize = 64;

pub(crate) type PrivkeySlice = [u8; PRIVATE_KEY_SIZE];
pub(crate) type PubkeySlice = ([u8; PUBLIC_KEY_UNCOMPRESSED_SIZE], usize);
pub(crate) type XOnlyPubkeySlice = [u8; X_ONLY_PUBLIC_KEY_SIZE];
pub(crate) type XOnlyPubkeyWithMaybeParity = ([u8; X_ONLY_PUBLIC_KEY_SIZE], Option<i32>);
pub(crate) type TweakSlice = [u8; TWEAK_SIZE];
pub(crate) type HashSlice = [u8; HASH_SIZE];
pub(crate) type ExtraDataSlice = [u8; EXTRA_DATA_SIZE];
pub(crate) type SignatureSlice = [u8; SIGNATURE_SIZE];

pub(crate) const ERROR_BAD_PRIVATE: usize = 0;
pub(crate) const ERROR_BAD_POINT: usize = 1;
// pub(crate) const ERROR_BAD_TWEAK: usize = 2;
// pub(crate) const ERROR_BAD_HASH: usize = 3;
pub(crate) const ERROR_BAD_SIGNATURE: usize = 4;
// pub(crate) const ERROR_BAD_EXTRA_DATA: usize = 5;
// pub(crate) const ERROR_BAD_PARITY: usize = 6;

#[allow(clippy::large_stack_arrays)]
pub(crate) static CONTEXT_BUFFER: [u8; 1_114_320] = [0; 1_114_320];
pub(crate) static mut CONTEXT: *const Context = core::ptr::null();
pub(crate) static mut CONTEXT_SET: bool = false;

pub(crate) fn get_context() -> *const Context {
    unsafe {
        if CONTEXT_SET {
            CONTEXT
        } else {
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
        Err(ERROR_BAD_PRIVATE)
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
        Err(ERROR_BAD_POINT)
    }
}

pub(crate) unsafe fn x_only_pubkey_parse(input: *const u8) -> InvalidInputResult<XOnlyPublicKey> {
    let mut pk = XOnlyPublicKey::new();
    if secp256k1_xonly_pubkey_parse(secp256k1_context_no_precomp, &mut pk, input) == 1 {
        Ok(pk)
    } else {
        Err(ERROR_BAD_POINT)
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
