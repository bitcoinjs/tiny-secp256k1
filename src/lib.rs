#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![no_std]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("Only `wasm32` target_arch is supported.");

#[panic_handler]
#[cfg(target_arch = "wasm32")]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

use core::ptr::NonNull;

use secp256k1_sys::{
    secp256k1_context_no_precomp, secp256k1_context_preallocated_create,
    secp256k1_context_preallocated_size, secp256k1_context_randomize, secp256k1_ec_pubkey_combine,
    secp256k1_ec_pubkey_create, secp256k1_ec_pubkey_parse, secp256k1_ec_pubkey_serialize,
    secp256k1_ec_pubkey_tweak_add, secp256k1_ec_pubkey_tweak_mul, secp256k1_ec_seckey_negate,
    secp256k1_ec_seckey_tweak_add, secp256k1_ecdsa_sign, secp256k1_ecdsa_signature_normalize,
    secp256k1_ecdsa_signature_parse_compact, secp256k1_ecdsa_signature_serialize_compact,
    secp256k1_ecdsa_verify, secp256k1_keypair_create, secp256k1_keypair_xonly_pub,
    secp256k1_nonce_function_rfc6979, secp256k1_schnorrsig_sign, secp256k1_schnorrsig_verify,
    secp256k1_xonly_pubkey_from_pubkey, secp256k1_xonly_pubkey_parse,
    secp256k1_xonly_pubkey_serialize, secp256k1_xonly_pubkey_tweak_add,
    secp256k1_xonly_pubkey_tweak_add_check, types::c_void, Context, KeyPair, PublicKey, Signature,
    XOnlyPublicKey, SECP256K1_SER_COMPRESSED, SECP256K1_SER_UNCOMPRESSED, SECP256K1_START_SIGN,
    SECP256K1_START_VERIFY,
};

use secp256k1_sys::recovery::{
    secp256k1_ecdsa_recover, secp256k1_ecdsa_recoverable_signature_parse_compact,
    secp256k1_ecdsa_recoverable_signature_serialize_compact, secp256k1_ecdsa_sign_recoverable,
    RecoverableSignature,
};

#[link(wasm_import_module = "./validate_error.js")]
extern "C" {
    #[link_name = "throwError"]
    fn throw_error(errcode: usize);
}

#[link(wasm_import_module = "./rand.js")]
extern "C" {
    #[link_name = "generateInt32"]
    fn generate_int32() -> i32;
}

type InvalidInputResult<T> = Result<T, usize>;

#[allow(clippy::large_stack_arrays)]
static CONTEXT_BUFFER: [u8; 192] = [0; 192];
static mut CONTEXT_SEED: [u8; 32] = [0; 32];

const PRIVATE_KEY_SIZE: usize = 32;
const PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;
const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
const X_ONLY_PUBLIC_KEY_SIZE: usize = 32;
const TWEAK_SIZE: usize = 32;
const HASH_SIZE: usize = 32;
const EXTRA_DATA_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;

const ERROR_BAD_PRIVATE: usize = 0;
const ERROR_BAD_POINT: usize = 1;
// const ERROR_BAD_TWEAK: usize = 2;
// const ERROR_BAD_HASH: usize = 3;
const ERROR_BAD_SIGNATURE: usize = 4;
// const ERROR_BAD_EXTRA_DATA: usize = 5;
// const ERROR_BAD_PARITY: usize = 6;

#[no_mangle]
pub static mut PRIVATE_INPUT: [u8; PRIVATE_KEY_SIZE] = [0; PRIVATE_KEY_SIZE];
#[no_mangle]
pub static mut PUBLIC_KEY_INPUT: [u8; PUBLIC_KEY_UNCOMPRESSED_SIZE] =
    [0; PUBLIC_KEY_UNCOMPRESSED_SIZE];
#[no_mangle]
pub static PUBLIC_KEY_INPUT2: [u8; PUBLIC_KEY_UNCOMPRESSED_SIZE] =
    [0; PUBLIC_KEY_UNCOMPRESSED_SIZE];
#[no_mangle]
pub static mut X_ONLY_PUBLIC_KEY_INPUT: [u8; X_ONLY_PUBLIC_KEY_SIZE] = [0; X_ONLY_PUBLIC_KEY_SIZE];
#[no_mangle]
pub static mut X_ONLY_PUBLIC_KEY_INPUT2: [u8; X_ONLY_PUBLIC_KEY_SIZE] = [0; X_ONLY_PUBLIC_KEY_SIZE];
#[no_mangle]
pub static mut TWEAK_INPUT: [u8; TWEAK_SIZE] = [0; TWEAK_SIZE];
#[no_mangle]
pub static HASH_INPUT: [u8; HASH_SIZE] = [0; HASH_SIZE];
#[no_mangle]
pub static EXTRA_DATA_INPUT: [u8; EXTRA_DATA_SIZE] = [0; EXTRA_DATA_SIZE];
#[no_mangle]
pub static mut SIGNATURE_INPUT: [u8; SIGNATURE_SIZE] = [0; SIGNATURE_SIZE];

macro_rules! jstry {
    ($value:expr) => {
        jstry!($value, ())
    };
    ($value:expr, $ret:expr) => {
        match $value {
            Ok(value) => value,
            Err(code) => {
                throw_error(code);
                return $ret;
            }
        }
    };
}

fn initialize_context_seed() {
    unsafe {
        for offset in (0..8).map(|v| v * 4) {
            let value = generate_int32();
            let bytes: [u8; 4] = value.to_ne_bytes();
            CONTEXT_SEED[offset..offset + 4].copy_from_slice(&bytes);
        }
    }
}

fn get_context() -> *const Context {
    static mut CONTEXT: *const Context = core::ptr::null();
    unsafe {
        if CONTEXT_SEED[0] == 0 {
            let size =
                secp256k1_context_preallocated_size(SECP256K1_START_SIGN | SECP256K1_START_VERIFY);
            assert_eq!(size, CONTEXT_BUFFER.len());
            let ctx = secp256k1_context_preallocated_create(
                NonNull::new(CONTEXT_BUFFER.as_ptr() as *mut c_void).expect("Not null"),
                SECP256K1_START_SIGN | SECP256K1_START_VERIFY,
            );
            initialize_context_seed();
            let retcode = secp256k1_context_randomize(ctx, CONTEXT_SEED.as_ptr());
            CONTEXT_SEED[0] = 1;
            CONTEXT_SEED[1..].fill(0);
            assert_eq!(retcode, 1);
            CONTEXT = ctx.as_ptr();
        }
        CONTEXT
    }
}

unsafe fn create_keypair(input: *const u8) -> InvalidInputResult<KeyPair> {
    let mut kp = KeyPair::new();
    if secp256k1_keypair_create(get_context(), &mut kp, input) == 1 {
        Ok(kp)
    } else {
        Err(ERROR_BAD_PRIVATE)
    }
}

unsafe fn x_only_pubkey_from_pubkey(input: *const u8, inputlen: usize) -> (XOnlyPublicKey, i32) {
    let mut xonly_pk = XOnlyPublicKey::new();
    let mut parity: i32 = 0;
    let pubkey = jstry!(pubkey_parse(input, inputlen), (xonly_pk, parity));
    x_only_pubkey_from_pubkey_struct(&mut xonly_pk, &mut parity, &pubkey)
}

unsafe fn x_only_pubkey_from_pubkey_struct(
    xonly_pk: &mut XOnlyPublicKey,
    parity: &mut i32,
    pubkey: &PublicKey,
) -> (XOnlyPublicKey, i32) {
    assert_eq!(
        secp256k1_xonly_pubkey_from_pubkey(get_context(), xonly_pk, parity, pubkey),
        1
    );
    (*xonly_pk, *parity)
}

unsafe fn pubkey_parse(input: *const u8, inputlen: usize) -> InvalidInputResult<PublicKey> {
    let mut pk = PublicKey::new();
    if secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &mut pk, input, inputlen) == 1 {
        Ok(pk)
    } else {
        Err(ERROR_BAD_POINT)
    }
}

unsafe fn x_only_pubkey_parse(input: *const u8) -> InvalidInputResult<XOnlyPublicKey> {
    let mut pk = XOnlyPublicKey::new();
    if secp256k1_xonly_pubkey_parse(secp256k1_context_no_precomp, &mut pk, input) == 1 {
        Ok(pk)
    } else {
        Err(ERROR_BAD_POINT)
    }
}

unsafe fn pubkey_serialize(pk: &PublicKey, output: *mut u8, mut outputlen: usize) {
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
            pk,
            flags,
        ),
        1
    );
}

unsafe fn x_only_pubkey_serialize(pk: &XOnlyPublicKey, output: *mut u8) {
    assert_eq!(
        secp256k1_xonly_pubkey_serialize(secp256k1_context_no_precomp, output, pk),
        1
    );
}

#[no_mangle]
#[export_name = "initializeContext"]
pub extern "C" fn initialize_context() {
    get_context();
}

#[no_mangle]
#[export_name = "isPoint"]
pub extern "C" fn is_point(inputlen: usize) -> usize {
    unsafe {
        if inputlen == X_ONLY_PUBLIC_KEY_SIZE {
            x_only_pubkey_parse(PUBLIC_KEY_INPUT.as_ptr()).map_or_else(|_error| 0, |_pk| 1)
        } else {
            pubkey_parse(PUBLIC_KEY_INPUT.as_ptr(), inputlen).map_or_else(|_error| 0, |_pk| 1)
        }
    }
}

// We know (ptrs.len() as i32) will not trunc or wrap since it is always 2.
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_possible_wrap)]
#[no_mangle]
#[export_name = "pointAdd"]
pub extern "C" fn point_add(inputlen: usize, inputlen2: usize, outputlen: usize) -> i32 {
    unsafe {
        let pk1 = jstry!(pubkey_parse(PUBLIC_KEY_INPUT.as_ptr(), inputlen), 0);
        let pk2 = jstry!(pubkey_parse(PUBLIC_KEY_INPUT2.as_ptr(), inputlen2), 0);
        let mut pk = PublicKey::new();
        let ptrs = [&pk1, &pk2];
        if secp256k1_ec_pubkey_combine(
            secp256k1_context_no_precomp,
            &mut pk,
            ptrs.as_ptr().cast::<*const PublicKey>(),
            ptrs.len() as i32,
        ) == 1
        {
            pubkey_serialize(&pk, PUBLIC_KEY_INPUT.as_mut_ptr(), outputlen);
            1
        } else {
            0
        }
    }
}

#[no_mangle]
#[export_name = "pointAddScalar"]
pub extern "C" fn point_add_scalar(inputlen: usize, outputlen: usize) -> i32 {
    unsafe {
        let mut pk = jstry!(pubkey_parse(PUBLIC_KEY_INPUT.as_ptr(), inputlen), 0);
        if secp256k1_ec_pubkey_tweak_add(get_context(), &mut pk, TWEAK_INPUT.as_ptr()) == 1 {
            pubkey_serialize(&pk, PUBLIC_KEY_INPUT.as_mut_ptr(), outputlen);
            1
        } else {
            0
        }
    }
}

#[no_mangle]
#[export_name = "xOnlyPointAddTweak"]
pub extern "C" fn x_only_point_add_tweak() -> i32 {
    unsafe {
        let mut xonly_pk = jstry!(x_only_pubkey_parse(X_ONLY_PUBLIC_KEY_INPUT.as_ptr()), 0);
        let mut pubkey = PublicKey::new();
        if secp256k1_xonly_pubkey_tweak_add(
            get_context(),
            &mut pubkey,
            &xonly_pk,
            TWEAK_INPUT.as_ptr(),
        ) != 1
        {
            // infinity point
            return -1;
        }
        let mut parity: i32 = 0;
        x_only_pubkey_from_pubkey_struct(&mut xonly_pk, &mut parity, &pubkey);
        x_only_pubkey_serialize(&xonly_pk, X_ONLY_PUBLIC_KEY_INPUT.as_mut_ptr());
        parity
    }
}

#[no_mangle]
#[export_name = "xOnlyPointAddTweakCheck"]
pub extern "C" fn x_only_point_add_tweak_check(tweaked_parity: i32) -> i32 {
    unsafe {
        let xonly_pk = jstry!(x_only_pubkey_parse(X_ONLY_PUBLIC_KEY_INPUT.as_ptr()), 0);
        let tweaked_key_ptr = X_ONLY_PUBLIC_KEY_INPUT2.as_ptr();
        jstry!(x_only_pubkey_parse(tweaked_key_ptr), 0);

        secp256k1_xonly_pubkey_tweak_add_check(
            get_context(),
            tweaked_key_ptr,
            tweaked_parity,
            &xonly_pk,
            TWEAK_INPUT.as_ptr(),
        )
    }
}

#[no_mangle]
#[export_name = "pointCompress"]
pub extern "C" fn point_compress(inputlen: usize, outputlen: usize) {
    unsafe {
        let pk = jstry!(pubkey_parse(PUBLIC_KEY_INPUT.as_ptr(), inputlen));
        pubkey_serialize(&pk, PUBLIC_KEY_INPUT.as_mut_ptr(), outputlen);
    }
}

#[no_mangle]
#[export_name = "pointFromScalar"]
pub extern "C" fn point_from_scalar(outputlen: usize) -> i32 {
    unsafe {
        let mut pk = PublicKey::new();
        if secp256k1_ec_pubkey_create(get_context(), &mut pk, PRIVATE_INPUT.as_ptr()) == 1 {
            pubkey_serialize(&pk, PUBLIC_KEY_INPUT.as_mut_ptr(), outputlen);
            1
        } else {
            0
        }
    }
}

#[allow(clippy::missing_panics_doc)]
#[no_mangle]
#[export_name = "xOnlyPointFromScalar"]
pub extern "C" fn x_only_point_from_scalar() -> i32 {
    unsafe {
        let keypair = jstry!(create_keypair(PRIVATE_INPUT.as_ptr()), 0);
        let mut xonly_pk = XOnlyPublicKey::new();
        let mut parity: i32 = 0; // TODO: Should we return this somehow?
        assert_eq!(
            secp256k1_keypair_xonly_pub(get_context(), &mut xonly_pk, &mut parity, &keypair),
            1
        );
        x_only_pubkey_serialize(&xonly_pk, X_ONLY_PUBLIC_KEY_INPUT.as_mut_ptr());
        1
    }
}

#[no_mangle]
#[export_name = "xOnlyPointFromPoint"]
pub extern "C" fn x_only_point_from_point(inputlen: usize) -> i32 {
    unsafe {
        let (xonly_pk, _parity) = x_only_pubkey_from_pubkey(PUBLIC_KEY_INPUT.as_ptr(), inputlen);
        x_only_pubkey_serialize(&xonly_pk, X_ONLY_PUBLIC_KEY_INPUT.as_mut_ptr());
        1
    }
}

#[no_mangle]
#[export_name = "pointMultiply"]
pub extern "C" fn point_multiply(inputlen: usize, outputlen: usize) -> i32 {
    unsafe {
        let mut pk = jstry!(pubkey_parse(PUBLIC_KEY_INPUT.as_ptr(), inputlen), 0);
        if secp256k1_ec_pubkey_tweak_mul(get_context(), &mut pk, TWEAK_INPUT.as_ptr()) == 1 {
            pubkey_serialize(&pk, PUBLIC_KEY_INPUT.as_mut_ptr(), outputlen);
            1
        } else {
            0
        }
    }
}

#[no_mangle]
#[export_name = "privateAdd"]
pub extern "C" fn private_add() -> i32 {
    unsafe {
        i32::from(
            secp256k1_ec_seckey_tweak_add(
                secp256k1_context_no_precomp,
                PRIVATE_INPUT.as_mut_ptr(),
                TWEAK_INPUT.as_ptr(),
            ) == 1,
        )
    }
}

#[allow(clippy::missing_panics_doc)]
#[no_mangle]
#[export_name = "privateSub"]
pub extern "C" fn private_sub() -> i32 {
    unsafe {
        assert_eq!(
            secp256k1_ec_seckey_negate(secp256k1_context_no_precomp, TWEAK_INPUT.as_mut_ptr()),
            1
        );
        i32::from(
            secp256k1_ec_seckey_tweak_add(
                secp256k1_context_no_precomp,
                PRIVATE_INPUT.as_mut_ptr(),
                TWEAK_INPUT.as_ptr(),
            ) == 1,
        )
    }
}

#[allow(clippy::missing_panics_doc)]
#[no_mangle]
#[export_name = "privateNegate"]
pub extern "C" fn private_negate() {
    unsafe {
        assert_eq!(
            secp256k1_ec_seckey_negate(secp256k1_context_no_precomp, PRIVATE_INPUT.as_mut_ptr()),
            1
        );
    }
}

#[allow(clippy::missing_panics_doc)]
#[no_mangle]
pub extern "C" fn sign(extra_data: i32) {
    unsafe {
        let mut sig = Signature::new();
        let noncedata = if extra_data == 0 {
            core::ptr::null()
        } else {
            EXTRA_DATA_INPUT.as_ptr()
        };

        assert_eq!(
            secp256k1_ecdsa_sign(
                get_context(),
                &mut sig,
                HASH_INPUT.as_ptr(),
                PRIVATE_INPUT.as_ptr(),
                secp256k1_nonce_function_rfc6979,
                noncedata.cast()
            ),
            1
        );

        assert_eq!(
            secp256k1_ecdsa_signature_serialize_compact(
                secp256k1_context_no_precomp,
                SIGNATURE_INPUT.as_mut_ptr(),
                &sig,
            ),
            1
        );
    }
}

#[allow(clippy::missing_panics_doc)]
#[no_mangle]
#[export_name = "signRecoverable"]
pub extern "C" fn sign_recoverable(extra_data: i32) -> i32 {
    unsafe {
        let mut sig = RecoverableSignature::new();
        let noncedata = if extra_data == 0 {
            core::ptr::null()
        } else {
            EXTRA_DATA_INPUT.as_ptr()
        };

        assert_eq!(
            secp256k1_ecdsa_sign_recoverable(
                get_context(),
                &mut sig,
                HASH_INPUT.as_ptr(),
                PRIVATE_INPUT.as_ptr(),
                secp256k1_nonce_function_rfc6979,
                noncedata.cast()
            ),
            1
        );

        let mut recid: i32 = 0;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(
            secp256k1_context_no_precomp,
            SIGNATURE_INPUT.as_mut_ptr(),
            &mut recid,
            &sig,
        );
        recid
    }
}

#[allow(clippy::missing_panics_doc)]
#[no_mangle]
#[export_name = "signSchnorr"]
pub extern "C" fn sign_schnorr(extra_data: i32) {
    unsafe {
        let mut keypair = KeyPair::new();
        let noncedata = if extra_data == 0 {
            core::ptr::null()
        } else {
            EXTRA_DATA_INPUT.as_ptr()
        }
        .cast::<c_void>();

        assert_eq!(
            secp256k1_keypair_create(get_context(), &mut keypair, PRIVATE_INPUT.as_ptr()),
            1
        );

        assert_eq!(
            secp256k1_schnorrsig_sign(
                get_context(),
                SIGNATURE_INPUT.as_mut_ptr(),
                HASH_INPUT.as_ptr(),
                &keypair,
                noncedata.cast()
            ),
            1
        );
    }
}

#[no_mangle]
pub extern "C" fn verify(inputlen: usize, strict: i32) -> i32 {
    unsafe {
        let pk = jstry!(pubkey_parse(PUBLIC_KEY_INPUT.as_ptr(), inputlen), 0);

        let mut signature = Signature::new();
        if secp256k1_ecdsa_signature_parse_compact(
            secp256k1_context_no_precomp,
            &mut signature,
            SIGNATURE_INPUT.as_ptr(),
        ) == 0
        {
            throw_error(ERROR_BAD_SIGNATURE);
            return 0;
        }

        if strict == 0 {
            secp256k1_ecdsa_signature_normalize(
                secp256k1_context_no_precomp,
                &mut signature,
                &signature,
            );
        }

        i32::from(secp256k1_ecdsa_verify(get_context(), &signature, HASH_INPUT.as_ptr(), &pk) == 1)
    }
}

#[no_mangle]
pub extern "C" fn recover(outputlen: usize, recid: i32) -> i32 {
    unsafe {
        let mut signature = RecoverableSignature::new();
        if secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1_context_no_precomp,
            &mut signature,
            SIGNATURE_INPUT.as_ptr(),
            recid,
        ) == 0
        {
            throw_error(ERROR_BAD_SIGNATURE);
            return 0;
        }

        let mut pk = PublicKey::new();
        if secp256k1_ecdsa_recover(get_context(), &mut pk, &signature, HASH_INPUT.as_ptr()) == 1 {
            pubkey_serialize(&pk, PUBLIC_KEY_INPUT.as_mut_ptr(), outputlen);
            1
        } else {
            0
        }
    }
}

#[no_mangle]
#[export_name = "verifySchnorr"]
pub extern "C" fn verify_schnorr() -> i32 {
    unsafe {
        let pk = jstry!(x_only_pubkey_parse(X_ONLY_PUBLIC_KEY_INPUT.as_ptr()), 0);
        i32::from(
            secp256k1_schnorrsig_verify(
                get_context(),
                SIGNATURE_INPUT.as_ptr(),
                HASH_INPUT.as_ptr(),
                32,
                &pk,
            ) == 1,
        )
    }
}
