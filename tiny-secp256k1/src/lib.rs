#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![cfg_attr(feature = "no_std", no_std)]

//! # tiny-secp256k1
//!
//! [![NPM](https://img.shields.io/npm/v/tiny-secp256k1.svg)](https://www.npmjs.org/package/tiny-secp256k1)
//! [![docs.rs](https://img.shields.io/docsrs/tiny-secp256k1)](https://docs.rs/tiny-secp256k1/latest/tiny_secp256k1/)
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
use core::convert::TryInto;

#[doc(inline)]
pub use context::set_context;
use context::{get_context, get_hcontext};
pub use error::Error;
pub use pubkey::{Pubkey, PubkeyRef};
use secp256k1::secp256k1_sys;

mod validate;
use validate::validate_tweak;

use secp256k1::{schnorrsig, Message, PublicKey, SecretKey};
use secp256k1_sys::{
    secp256k1_context_no_precomp, secp256k1_ec_seckey_negate, secp256k1_ec_seckey_tweak_add,
    secp256k1_ecdsa_sign, secp256k1_ecdsa_signature_normalize,
    secp256k1_ecdsa_signature_parse_compact, secp256k1_ecdsa_signature_serialize_compact,
    secp256k1_ecdsa_verify, secp256k1_nonce_function_rfc6979, secp256k1_schnorrsig_verify,
    types::c_void, Signature,
};

use consts::{ORDER, PRIVATE_KEY_SIZE, SIGNATURE_SIZE, TWEAK_SIZE, X_ONLY_PUBLIC_KEY_SIZE, ZERO32};
use types::{
    ExtraDataSlice, HashSlice, InvalidInputResult, PrivkeySlice, SignatureSlice, TweakSlice,
    XOnlyPubkeySlice, XOnlyPubkeyWithMaybeParity, XOnlyPubkeyWithParity,
};
use utils::{assume_compression, pubkey_parse, x_only_pubkey_parse};

pub fn is_point(pubkey: &PubkeyRef) -> bool {
    let len = pubkey.len();
    if len == X_ONLY_PUBLIC_KEY_SIZE {
        schnorrsig::PublicKey::from_slice(pubkey.as_slice()).map_or_else(|_error| false, |_pk| true)
    } else {
        PublicKey::from_slice(pubkey.as_slice()).map_or_else(|_error| false, |_pk| true)
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
    let compressed = assume_compression(compressed, Some(pubkey1.len()));
    let key1 = PublicKey::from_slice(pubkey1.as_slice()).map_err(|_| Error::BadPoint)?;
    let key2 = PublicKey::from_slice(pubkey2.as_slice()).map_err(|_| Error::BadPoint)?;

    Ok(key1.combine(&key2).map_or_else(
        |_| None,
        |v| {
            Some(if compressed == 33 {
                Pubkey::Compressed(v.serialize())
            } else {
                Pubkey::Uncompressed(v.serialize_uncompressed())
            })
        },
    ))
}

pub fn point_add_scalar(
    pubkey: &PubkeyRef,
    tweak: &TweakSlice,
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Pubkey>> {
    let outputlen = assume_compression(compressed, Some(pubkey.len()));
    let mut key = PublicKey::from_slice(pubkey.as_slice()).map_err(|_| Error::BadPoint)?;
    validate_tweak(tweak)?;
    Ok(key.add_exp_assign(get_hcontext(), &tweak[..]).map_or_else(
        |_| None,
        |_| {
            Some(if outputlen == 33 {
                Pubkey::Compressed(key.serialize())
            } else {
                Pubkey::Uncompressed(key.serialize_uncompressed())
            })
        },
    ))
}

pub fn x_only_point_add_tweak(
    pubkey: &XOnlyPubkeySlice,
    tweak: &TweakSlice,
) -> InvalidInputResult<Option<XOnlyPubkeyWithParity>> {
    let mut key = schnorrsig::PublicKey::from_slice(pubkey).map_err(|_| Error::BadPoint)?;
    validate_tweak(tweak)?;
    let parity = key.tweak_add_assign(get_hcontext(), tweak);
    if let Ok(parity) = parity {
        Ok(Some((key.serialize(), if parity { 1_i32 } else { 0_i32 })))
    } else {
        Ok(None)
    }
}

pub fn x_only_point_add_tweak_check(
    pubkey: &XOnlyPubkeySlice,
    result: &XOnlyPubkeyWithMaybeParity,
    tweak: &TweakSlice,
) -> InvalidInputResult<bool> {
    // Currently there is almost no difference between
    // secp256k1_xonly_pubkey_tweak_add_check and doing it over and checking equality.
    // Later on, performance gains might be added for having parity, so we implement it.
    if let Some(parity) = result.1 {
        let pubkey = schnorrsig::PublicKey::from_slice(pubkey).map_err(|_| Error::BadPoint)?;
        let result = schnorrsig::PublicKey::from_slice(&result.0).map_err(|_| Error::BadPoint)?;
        Ok(pubkey.tweak_add_check(get_hcontext(), &result, parity != 0, *tweak))
    } else {
        x_only_point_add_tweak(pubkey, tweak)?.map_or(Ok(false), |v| Ok(v.0 == result.0))
    }
}

pub fn point_compress(pubkey: &PubkeyRef, compressed: Option<bool>) -> InvalidInputResult<Pubkey> {
    let outputlen = assume_compression(compressed, Some(pubkey.len()));
    let key = PublicKey::from_slice(pubkey.as_slice()).map_err(|_| Error::BadPoint)?;
    Ok(if outputlen == 33 {
        Pubkey::Compressed(key.serialize())
    } else {
        Pubkey::Uncompressed(key.serialize_uncompressed())
    })
}

pub fn point_from_scalar(
    private: &PrivkeySlice,
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Pubkey>> {
    let compressed = assume_compression(compressed, None);
    let pk = SecretKey::from_slice(private).map_err(|_| Error::BadPrivate)?;
    let pb = PublicKey::from_secret_key(get_hcontext(), &pk);
    Ok(Some(if compressed == 33 {
        Pubkey::Compressed(pb.serialize())
    } else {
        Pubkey::Uncompressed(pb.serialize_uncompressed())
    }))
}

#[allow(clippy::missing_panics_doc)]
pub fn x_only_point_from_scalar(
    private: &PrivkeySlice,
) -> InvalidInputResult<XOnlyPubkeyWithParity> {
    let pk = SecretKey::from_slice(private).map_err(|_| Error::BadPrivate)?;
    let pb = PublicKey::from_secret_key(get_hcontext(), &pk);
    let ser = pb.serialize();
    Ok((
        ser[1..33].try_into().expect("32 bytes"),
        (ser[0] & 1) as i32,
    ))
}

pub fn x_only_point_from_point(pubkey: &PubkeyRef) -> InvalidInputResult<XOnlyPubkeyWithParity> {
    let pb = PublicKey::from_slice(pubkey.as_slice()).map_err(|_| Error::BadPoint)?;
    let ser = pb.serialize();
    Ok((
        ser[1..33].try_into().expect("32 bytes"),
        (ser[0] & 1) as i32,
    ))
}

pub fn point_multiply(
    pubkey: &PubkeyRef,
    tweak: &TweakSlice,
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Pubkey>> {
    let outputlen = assume_compression(compressed, Some(pubkey.len()));
    let mut pb = PublicKey::from_slice(pubkey.as_slice()).map_err(|_| Error::BadPoint)?;
    validate_tweak(tweak)?;
    if let Ok(_) = pb.mul_assign(get_hcontext(), tweak) {
        Ok(Some(if outputlen == 33 {
            Pubkey::Compressed(pb.serialize())
        } else {
            Pubkey::Uncompressed(pb.serialize_uncompressed())
        }))
    } else {
        Ok(None)
    }
}

pub fn private_add(
    private: &PrivkeySlice,
    tweak: &TweakSlice,
) -> InvalidInputResult<Option<PrivkeySlice>> {
    validate_tweak(tweak)?;
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
    validate_tweak(tweak)?;
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
    let secp = get_hcontext();
    let kp =
        schnorrsig::KeyPair::from_seckey_slice(secp, private).map_err(|_| Error::BadPrivate)?;
    let msg = Message::from_slice(hash).map_err(|_| Error::BadHash)?;
    let nonce = extra_data.map_or(&ZERO32, |v| v);
    let sig = secp.schnorrsig_sign_with_aux_rand(&msg, &kp, nonce);
    Ok(*sig.as_ref())
}

pub fn verify(
    hash: &HashSlice,
    pubkey: &PubkeyRef,
    sig: &SignatureSlice,
    strict: Option<bool>,
) -> InvalidInputResult<bool> {
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
    unsafe {
        let pk = x_only_pubkey_parse(pubkey.as_ptr())?;
        if secp256k1_schnorrsig_verify(get_context(), signature.as_ptr(), hash.as_ptr(), &pk) == 1 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
