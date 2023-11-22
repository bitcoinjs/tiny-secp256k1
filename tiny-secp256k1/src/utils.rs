use crate::{
    consts::{PUBLIC_KEY_COMPRESSED_SIZE, PUBLIC_KEY_UNCOMPRESSED_SIZE},
    types::{ExtraDataSlice, SignatureSlice, SIGNATURE_SIZE},
};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId, Signature},
    ffi::{self, CPtr},
    AllPreallocated, Message, Secp256k1, SecretKey,
};

pub fn assume_compression(compressed: Option<bool>, p: Option<usize>) -> usize {
    // To allow for XOnly PubkeyRef length to indicate compressed,
    // We bitwise OR 1 (32 -> 33, while 33 and 65 stay unchanged)
    compressed.map_or_else(
        || p.map_or(PUBLIC_KEY_COMPRESSED_SIZE, |v| v | 1),
        |v| {
            if v {
                PUBLIC_KEY_COMPRESSED_SIZE
            } else {
                PUBLIC_KEY_UNCOMPRESSED_SIZE
            }
        },
    )
}

// TODO: Get ecdsa sign and sign_recoverable to accept extra entropy for rfc6979
pub fn sign_ecdsa(
    secp: &'static Secp256k1<AllPreallocated<'static>>,
    msg: Message,
    sec: SecretKey,
    extra_data: Option<&ExtraDataSlice>,
) -> Signature {
    unsafe {
        let mut sig = ffi::Signature::new();
        let noncedata = extra_data
            .map_or(core::ptr::null(), |v| v.as_ptr())
            .cast::<ffi::types::c_void>();

        assert_eq!(
            ffi::secp256k1_ecdsa_sign(
                secp.ctx().as_ptr(),
                &mut sig,
                msg.as_c_ptr(),
                sec.as_c_ptr(),
                ffi::secp256k1_nonce_function_rfc6979,
                noncedata
            ),
            1
        );

        let mut output: SignatureSlice = [0_u8; SIGNATURE_SIZE];
        assert_eq!(
            ffi::secp256k1_ecdsa_signature_serialize_compact(
                ffi::secp256k1_context_no_precomp,
                output.as_mut_ptr(),
                &sig,
            ),
            1
        );
        Signature::from_compact(&output).unwrap()
    }
}

// TODO: Get ecdsa sign and sign_recoverable to accept extra entropy for rfc6979
pub fn sign_ecdsa_recoverable(
    secp: &'static Secp256k1<AllPreallocated<'static>>,
    msg: Message,
    sec: SecretKey,
    extra_data: Option<&ExtraDataSlice>,
) -> RecoverableSignature {
    unsafe {
        let mut sig = ffi::recovery::RecoverableSignature::new();
        let noncedata = extra_data
            .map_or(core::ptr::null(), |v| v.as_ptr())
            .cast::<ffi::types::c_void>();

        assert_eq!(
            ffi::recovery::secp256k1_ecdsa_sign_recoverable(
                secp.ctx().as_ptr(),
                &mut sig,
                msg.as_c_ptr(),
                sec.as_c_ptr(),
                ffi::secp256k1_nonce_function_rfc6979,
                noncedata
            ),
            1
        );

        let mut output: SignatureSlice = [0_u8; SIGNATURE_SIZE];
        let mut recid: i32 = 0;

        assert_eq!(
            ffi::recovery::secp256k1_ecdsa_recoverable_signature_serialize_compact(
                ffi::secp256k1_context_no_precomp,
                output.as_mut_ptr(),
                &mut recid,
                &sig,
            ),
            1
        );
        RecoverableSignature::from_compact(&output, RecoveryId::from_i32(recid).unwrap()).unwrap()
    }
}
