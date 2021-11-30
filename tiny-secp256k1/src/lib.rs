#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![cfg_attr(feature = "no_std", no_std)]

//! # tiny-secp256k1
//!
//! [![NPM](https://img.shields.io/npm/v/tiny-secp256k1.svg)](https://www.npmjs.org/package/tiny-secp256k1)
//!
//! This library is under development, and, like the [secp256k1](https://github.com/bitcoin-core/secp256k1)
//! C library (through [secp256k1-sys](https://github.com/rust-bitcoin/rust-secp256k1/) Rust crate) it depends
//! on, this is a research effort to determine an optimal API for end-users of the bitcoinjs ecosystem.
//!
//! ## Examples
//!
//! ### Private keys
//! 32 byte sized slices.
//! ```
//! use rand::{self, RngCore};
//! use tiny_secp256k1::{is_private, point_from_scalar, point_add_scalar, Pubkey, PubkeyRef};
//!
//! let mut privkey = [0_u8; 32];
//!
//! // 0 is not a valid private key, so this will run at least once (most likely only once)
//! while !is_private(&privkey) {
//!     rand::thread_rng().fill_bytes(&mut privkey);
//! }
//!
//! let pkey = point_from_scalar(&privkey, None).unwrap().unwrap();
//! println!("{:?}", pkey);
//! // Ok(Some(Compressed([3, 126, 249, 27, 122, 231, 178, 211, ...])))
//! ```

mod consts;
mod context;
mod error;
mod pubkey;
mod types;
mod utils;
use context::get_context;
#[doc(inline)]
pub use context::set_context;
pub use error::Error;
pub use pubkey::{Pubkey, PubkeyRef};

#[cfg(not(feature = "minimal_validation"))]
mod validate;
#[cfg(not(feature = "minimal_validation"))]
use validate::{validate_parity, validate_private, validate_signature, validate_tweak};

use secp256k1_sys::{
    secp256k1_context_no_precomp, secp256k1_ec_pubkey_combine, secp256k1_ec_pubkey_create,
    secp256k1_ec_pubkey_tweak_add, secp256k1_ec_pubkey_tweak_mul, secp256k1_ec_seckey_negate,
    secp256k1_ec_seckey_tweak_add, secp256k1_ecdsa_sign, secp256k1_ecdsa_signature_normalize,
    secp256k1_ecdsa_signature_parse_compact, secp256k1_ecdsa_signature_serialize_compact,
    secp256k1_ecdsa_verify, secp256k1_keypair_create, secp256k1_keypair_xonly_pub,
    secp256k1_nonce_function_bip340, secp256k1_nonce_function_rfc6979, secp256k1_schnorrsig_sign,
    secp256k1_schnorrsig_verify, secp256k1_xonly_pubkey_tweak_add,
    secp256k1_xonly_pubkey_tweak_add_check, types::c_void, KeyPair, PublicKey, Signature,
    XOnlyPublicKey,
};

use consts::{ORDER, PRIVATE_KEY_SIZE, SIGNATURE_SIZE, TWEAK_SIZE, X_ONLY_PUBLIC_KEY_SIZE, ZERO32};
use types::{
    ExtraDataSlice, HashSlice, InvalidInputResult, PrivkeySlice, SignatureSlice, TweakSlice,
    XOnlyPubkeySlice, XOnlyPubkeyWithMaybeParity, XOnlyPubkeyWithParity,
};
use utils::{
    assume_compression, create_keypair, pubkey_parse, pubkey_serialize, x_only_pubkey_from_pubkey,
    x_only_pubkey_from_pubkey_struct, x_only_pubkey_parse, x_only_pubkey_serialize,
};

pub fn is_point(pubkey: &PubkeyRef) -> bool {
    unsafe {
        let len = pubkey.len();
        if len == X_ONLY_PUBLIC_KEY_SIZE {
            x_only_pubkey_parse(pubkey.as_ptr()).map_or_else(|_error| false, |_pk| true)
        } else {
            pubkey_parse(pubkey).map_or_else(|_error| false, |_pk| true)
        }
    }
}

pub fn is_private(v: &PrivkeySlice) -> bool {
    v > &ZERO32 && v < &ORDER
}

// We know (ptrs.len() as i32) will not trunc or wrap since it is always 2.
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_possible_wrap)]
pub fn point_add(
    pubkey1: &PubkeyRef,
    pubkey2: &PubkeyRef,
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Pubkey>> {
    let outputlen = assume_compression(compressed, Some(pubkey1.len()));
    unsafe {
        let pk1 = pubkey_parse(pubkey1)?;
        let pk2 = pubkey_parse(pubkey2)?;
        let mut pk = PublicKey::new();
        let ptrs = [pk1.as_ptr(), pk2.as_ptr()];
        if secp256k1_ec_pubkey_combine(
            secp256k1_context_no_precomp,
            &mut pk,
            ptrs.as_ptr().cast::<*const PublicKey>(),
            ptrs.len() as i32,
        ) == 1
        {
            let mut output = Pubkey::new_from_len(outputlen);
            pubkey_serialize(&pk, output.as_mut_ptr(), outputlen);
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }
}

pub fn point_add_scalar(
    pubkey: &PubkeyRef,
    tweak: &TweakSlice,
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Pubkey>> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        validate_tweak(tweak)?;
    }
    let outputlen = assume_compression(compressed, Some(pubkey.len()));
    unsafe {
        let mut pk = pubkey_parse(pubkey)?;
        if secp256k1_ec_pubkey_tweak_add(
            get_context(),
            pk.as_mut_ptr().cast::<PublicKey>(),
            tweak.as_ptr(),
        ) == 1
        {
            let mut output = Pubkey::new_from_len(outputlen);
            pubkey_serialize(&pk, output.as_mut_ptr(), outputlen);
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }
}

pub fn x_only_point_add_tweak(
    pubkey: &XOnlyPubkeySlice,
    tweak: &TweakSlice,
) -> InvalidInputResult<Option<XOnlyPubkeyWithParity>> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        // XOnlyPubkeySlice is specific enough a type we don't need simple checks
        validate_tweak(tweak)?;
    }
    unsafe {
        let mut xonly_pk = x_only_pubkey_parse(pubkey.as_ptr())?;
        let mut pubkey = PublicKey::new();
        if secp256k1_xonly_pubkey_tweak_add(get_context(), &mut pubkey, &xonly_pk, tweak.as_ptr())
            != 1
        {
            // infinity point
            return Ok(None);
        }
        let mut parity: i32 = 0;
        x_only_pubkey_from_pubkey_struct(&mut xonly_pk, &mut parity, &pubkey);
        let mut output = ([0_u8; X_ONLY_PUBLIC_KEY_SIZE], parity);
        x_only_pubkey_serialize(&xonly_pk, output.0.as_mut_ptr());
        Ok(Some(output))
    }
}

pub fn x_only_point_add_tweak_check(
    pubkey: &XOnlyPubkeySlice,
    result: &XOnlyPubkeyWithMaybeParity,
    tweak: &TweakSlice,
) -> InvalidInputResult<bool> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        // XOnlyPubkeySlice is specific enough a type we don't need simple checks
        validate_parity(result.1.unwrap_or(0))?;
        validate_tweak(tweak)?;
    }
    // Currently there is almost no difference between
    // secp256k1_xonly_pubkey_tweak_add_check and doing it over and checking equality.
    // Later on, performance gains might be added for having parity, so we implement it.
    if let Some(parity) = result.1 {
        unsafe {
            let xonly_pk = x_only_pubkey_parse(pubkey.as_ptr())?;
            let tweaked_key_ptr = result.0.as_ptr();
            x_only_pubkey_parse(tweaked_key_ptr)?;

            Ok(secp256k1_xonly_pubkey_tweak_add_check(
                get_context(),
                tweaked_key_ptr,
                parity,
                &xonly_pk,
                tweak.as_ptr(),
            ) == 1)
        }
    } else {
        x_only_point_add_tweak(pubkey, tweak)?.map_or(Ok(false), |v| Ok(v.0 == result.0))
    }
}

pub fn point_compress(pubkey: &PubkeyRef, compressed: Option<bool>) -> InvalidInputResult<Pubkey> {
    let outputlen = assume_compression(compressed, Some(pubkey.len()));
    unsafe {
        let pk = pubkey_parse(pubkey)?;
        let mut output = Pubkey::new_from_len(outputlen);
        pubkey_serialize(&pk, output.as_mut_ptr(), outputlen);
        Ok(output)
    }
}

pub fn point_from_scalar(
    private: &PrivkeySlice,
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Pubkey>> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        validate_private(private)?;
    }
    let outputlen = assume_compression(compressed, None);
    unsafe {
        let mut pk = PublicKey::new();
        if secp256k1_ec_pubkey_create(get_context(), &mut pk, private.as_ptr()) == 1 {
            let mut output = Pubkey::new_from_len(outputlen);
            pubkey_serialize(&pk, output.as_mut_ptr(), outputlen);
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn x_only_point_from_scalar(
    private: &PrivkeySlice,
) -> InvalidInputResult<XOnlyPubkeyWithParity> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        validate_private(private)?;
    }
    unsafe {
        let keypair = create_keypair(private.as_ptr())?;
        let mut xonly_pk = XOnlyPublicKey::new();
        let mut parity: i32 = 0;
        assert_eq!(
            secp256k1_keypair_xonly_pub(get_context(), &mut xonly_pk, &mut parity, &keypair),
            1
        );
        let mut output = ([0_u8; 32], parity);
        x_only_pubkey_serialize(&xonly_pk, output.0.as_mut_ptr());
        Ok(output)
    }
}

pub fn x_only_point_from_point(pubkey: &PubkeyRef) -> InvalidInputResult<XOnlyPubkeyWithParity> {
    unsafe {
        let (xonly_pk, parity) = x_only_pubkey_from_pubkey(pubkey)?;
        let mut output = ([0_u8; 32], parity);
        x_only_pubkey_serialize(&xonly_pk, output.0.as_mut_ptr());
        Ok(output)
    }
}

pub fn point_multiply(
    pubkey: &PubkeyRef,
    tweak: &TweakSlice,
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Pubkey>> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        validate_tweak(tweak)?;
    }
    let outputlen = assume_compression(compressed, Some(pubkey.len()));
    unsafe {
        let mut pk = pubkey_parse(pubkey)?;
        if secp256k1_ec_pubkey_tweak_mul(get_context(), &mut pk, tweak.as_ptr()) == 1 {
            let mut output = Pubkey::new_from_len(outputlen);
            pubkey_serialize(&pk, output.as_mut_ptr(), outputlen);
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }
}

pub fn private_add(
    private: &PrivkeySlice,
    tweak: &TweakSlice,
) -> InvalidInputResult<Option<PrivkeySlice>> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        validate_private(private)?;
        validate_tweak(tweak)?;
    }
    let mut output: PrivkeySlice = [0_u8; PRIVATE_KEY_SIZE];
    output.copy_from_slice(private);

    unsafe {
        if secp256k1_ec_seckey_tweak_add(
            secp256k1_context_no_precomp,
            output.as_mut_ptr(),
            tweak.as_ptr(),
        ) == 1
        {
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn private_sub(
    private: &PrivkeySlice,
    tweak: &TweakSlice,
) -> InvalidInputResult<Option<PrivkeySlice>> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        validate_private(private)?;
        validate_tweak(tweak)?;
    }
    let mut output: PrivkeySlice = [0_u8; PRIVATE_KEY_SIZE];
    output.copy_from_slice(private);

    // If tweak is 0, x - 0 = x. Also, secp256k1_ec_seckey_negate will error
    // if we try to negate 0.
    if tweak == &ZERO32 {
        return Ok(Some(output));
    }

    let mut tweak_c: TweakSlice = [0_u8; TWEAK_SIZE];
    tweak_c.copy_from_slice(tweak);

    unsafe {
        assert_eq!(
            secp256k1_ec_seckey_negate(secp256k1_context_no_precomp, tweak_c.as_mut_ptr()),
            1
        );
        if secp256k1_ec_seckey_tweak_add(
            secp256k1_context_no_precomp,
            output.as_mut_ptr(),
            tweak_c.as_ptr(),
        ) == 1
        {
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn sign(
    hash: &HashSlice,
    private: &PrivkeySlice,
    extra_data: Option<&ExtraDataSlice>,
) -> InvalidInputResult<SignatureSlice> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        validate_private(private)?;
    }
    unsafe {
        let mut sig = Signature::new();
        let noncedata = extra_data
            .map_or(core::ptr::null(), |v| v.as_ptr())
            .cast::<c_void>();

        assert_eq!(
            secp256k1_ecdsa_sign(
                get_context(),
                &mut sig,
                hash.as_ptr(),
                private.as_ptr(),
                secp256k1_nonce_function_rfc6979,
                noncedata
            ),
            1
        );

        let mut output: SignatureSlice = [0_u8; SIGNATURE_SIZE];
        assert_eq!(
            secp256k1_ecdsa_signature_serialize_compact(
                secp256k1_context_no_precomp,
                output.as_mut_ptr(),
                &sig,
            ),
            1
        );
        Ok(output)
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn sign_schnorr(
    hash: &HashSlice,
    private: &PrivkeySlice,
    extra_data: Option<&ExtraDataSlice>,
) -> InvalidInputResult<SignatureSlice> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        validate_private(private)?;
    }
    unsafe {
        let mut keypair = KeyPair::new();
        let noncedata = extra_data.map_or(&ZERO32, |v| v).as_ptr().cast::<c_void>();

        assert_eq!(
            secp256k1_keypair_create(get_context(), &mut keypair, private.as_ptr()),
            1
        );

        let mut output: SignatureSlice = [0_u8; SIGNATURE_SIZE];
        assert_eq!(
            secp256k1_schnorrsig_sign(
                get_context(),
                output.as_mut_ptr(),
                hash.as_ptr(),
                &keypair,
                secp256k1_nonce_function_bip340,
                noncedata
            ),
            1
        );
        Ok(output)
    }
}

pub fn verify(
    hash: &HashSlice,
    pubkey: &PubkeyRef,
    sig: &SignatureSlice,
    strict: Option<bool>,
) -> InvalidInputResult<bool> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        validate_signature(sig)?;
    }
    unsafe {
        let pk = pubkey_parse(pubkey)?;

        let mut signature = Signature::new();
        if secp256k1_ecdsa_signature_parse_compact(
            secp256k1_context_no_precomp,
            &mut signature,
            sig.as_ptr(),
        ) == 0
        {
            return Err(Error::BadSignature);
        }

        if !strict.unwrap_or(false) {
            secp256k1_ecdsa_signature_normalize(
                secp256k1_context_no_precomp,
                &mut signature,
                &signature,
            );
        }

        if secp256k1_ecdsa_verify(get_context(), &signature, hash.as_ptr(), &pk) == 1 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub fn verify_schnorr(
    hash: &HashSlice,
    pubkey: &XOnlyPubkeySlice,
    signature: &SignatureSlice,
) -> InvalidInputResult<bool> {
    #[cfg(not(feature = "minimal_validation"))]
    {
        validate_signature(signature)?;
    }
    unsafe {
        let pk = x_only_pubkey_parse(pubkey.as_ptr())?;
        if secp256k1_schnorrsig_verify(get_context(), signature.as_ptr(), hash.as_ptr(), &pk) == 1 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
