#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::must_use_candidate)]
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

use context::get_hcontext;
#[doc(inline)]
pub use context::set_context;
pub use error::Error;
pub use pubkey::{Pubkey, PubkeyRef};
use secp256k1::{
    ecdsa::{RecoverableSignature, Signature},
    schnorr, Parity,
};

mod validate;
use validate::validate_tweak;

pub use secp256k1::ecdsa::RecoveryId;
use secp256k1::{KeyPair, Message, PublicKey, SecretKey, XOnlyPublicKey};

use consts::{ORDER, P_MINUS_N, X_ONLY_PUBLIC_KEY_SIZE, ZERO32};
use types::{
    ExtraDataSlice, HashSlice, InvalidInputResult, PrivkeySlice, SignatureSlice, TweakSlice,
    XOnlyPubkeySlice, XOnlyPubkeyWithMaybeParity, XOnlyPubkeyWithParity,
};
use utils::assume_compression;

pub fn is_point(pubkey: &PubkeyRef) -> bool {
    let len = pubkey.len();
    if len == X_ONLY_PUBLIC_KEY_SIZE {
        XOnlyPublicKey::from_slice(pubkey.as_slice()).map_or_else(|_error| false, |_pk| true)
    } else {
        PublicKey::from_slice(pubkey.as_slice()).map_or_else(|_error| false, |_pk| true)
    }
}

pub fn is_private(v: &PrivkeySlice) -> bool {
    v > &ZERO32 && v < &ORDER
}

/// # Errors
/// `Error::BadPoint` returned if `pubkey1` or `pubkey2` is invalid.
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

/// # Errors
/// `Error::BadPoint` returned if `pubkey` is invalid.
/// `Error::BadTweak` returned if `tweak` is invalid.
pub fn point_add_scalar(
    pubkey: &PubkeyRef,
    tweak: &TweakSlice,
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Pubkey>> {
    let outputlen = assume_compression(compressed, Some(pubkey.len()));
    let mut key = PublicKey::from_slice(pubkey.as_slice()).map_err(|_| Error::BadPoint)?;
    validate_tweak(tweak)?;
    Ok(key
        .add_exp_assign(get_hcontext(), tweak.as_slice())
        .map_or_else(
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

/// # Errors
/// `Error::BadPoint` returned if `pubkey` is invalid.
/// `Error::BadTweak` returned if `tweak` is invalid.
pub fn x_only_point_add_tweak(
    pubkey: &XOnlyPubkeySlice,
    tweak: &TweakSlice,
) -> InvalidInputResult<Option<XOnlyPubkeyWithParity>> {
    let mut key = XOnlyPublicKey::from_slice(pubkey).map_err(|_| Error::BadPoint)?;
    validate_tweak(tweak)?;
    let parity = key.tweak_add_assign(get_hcontext(), tweak);
    if let Ok(parity) = parity {
        Ok(Some((key.serialize(), parity.to_i32())))
    } else {
        Ok(None)
    }
}

/// # Errors
/// `Error::BadPoint` returned if `pubkey` or `result` is invalid.
/// `Error::BadTweak` returned if `tweak` is invalid.
/// `Error::BadParity` returned if `result` has `parity` and it is invalid.
pub fn x_only_point_add_tweak_check(
    pubkey: &XOnlyPubkeySlice,
    result: &XOnlyPubkeyWithMaybeParity,
    tweak: &TweakSlice,
) -> InvalidInputResult<bool> {
    // Currently there is almost no difference between
    // secp256k1_xonly_pubkey_tweak_add_check and doing it over and checking equality.
    // Later on, performance gains might be added for having parity, so we implement it.
    if let Some(parity) = result.1 {
        let pubkey = XOnlyPublicKey::from_slice(pubkey).map_err(|_| Error::BadPoint)?;
        let result = XOnlyPublicKey::from_slice(&result.0).map_err(|_| Error::BadPoint)?;
        let parity = Parity::from_i32(parity).map_err(|_| Error::BadParity)?;
        Ok(pubkey.tweak_add_check(get_hcontext(), &result, parity, *tweak))
    } else {
        x_only_point_add_tweak(pubkey, tweak)?.map_or(Ok(false), |v| Ok(v.0 == result.0))
    }
}

/// # Errors
/// `Error::BadPoint` returned if `pubkey` is invalid.
pub fn point_compress(pubkey: &PubkeyRef, compressed: Option<bool>) -> InvalidInputResult<Pubkey> {
    let outputlen = assume_compression(compressed, Some(pubkey.len()));
    let key = PublicKey::from_slice(pubkey.as_slice()).map_err(|_| Error::BadPoint)?;
    Ok(if outputlen == 33 {
        Pubkey::Compressed(key.serialize())
    } else {
        Pubkey::Uncompressed(key.serialize_uncompressed())
    })
}

/// # Errors
/// `Error::BadPrivate` returned if `private` is invalid.
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

/// # Errors
/// `Error::BadPrivate` returned if `private` is invalid.
pub fn x_only_point_from_scalar(
    private: &PrivkeySlice,
) -> InvalidInputResult<XOnlyPubkeyWithParity> {
    let pk = SecretKey::from_slice(private).map_err(|_| Error::BadPrivate)?;
    let pb = PublicKey::from_secret_key(get_hcontext(), &pk);
    let ser = pb.serialize();
    Ok((
        ser[1..33].try_into().expect("32 bytes"),
        i32::from(ser[0] & 1),
    ))
}

/// # Errors
/// `Error::BadPoint` returned if `pubkey` is invalid.
pub fn x_only_point_from_point(pubkey: &PubkeyRef) -> InvalidInputResult<XOnlyPubkeyWithParity> {
    let pb = PublicKey::from_slice(pubkey.as_slice()).map_err(|_| Error::BadPoint)?;
    let ser = pb.serialize();
    Ok((
        ser[1..33].try_into().expect("32 bytes"),
        i32::from(ser[0] & 1),
    ))
}

/// # Errors
/// `Error::BadPoint` returned if `pubkey` is invalid.
/// `Error::BadTweak` returned if `tweak` is invalid.
pub fn point_multiply(
    pubkey: &PubkeyRef,
    tweak: &TweakSlice,
    compressed: Option<bool>,
) -> InvalidInputResult<Option<Pubkey>> {
    let outputlen = assume_compression(compressed, Some(pubkey.len()));
    let mut pb = PublicKey::from_slice(pubkey.as_slice()).map_err(|_| Error::BadPoint)?;
    validate_tweak(tweak)?;
    if pb.mul_assign(get_hcontext(), tweak).is_ok() {
        Ok(Some(if outputlen == 33 {
            Pubkey::Compressed(pb.serialize())
        } else {
            Pubkey::Uncompressed(pb.serialize_uncompressed())
        }))
    } else {
        Ok(None)
    }
}

/// # Errors
/// `Error::BadPrivate` returned if `private` is invalid.
/// `Error::BadTweak` returned if `tweak` is invalid.
pub fn private_add(
    private: &PrivkeySlice,
    tweak: &TweakSlice,
) -> InvalidInputResult<Option<PrivkeySlice>> {
    validate_tweak(tweak)?;
    let mut sec = SecretKey::from_slice(private.as_slice()).map_err(|_| Error::BadPrivate)?;
    if sec.add_assign(tweak.as_slice()).is_ok() {
        Ok(Some(sec.serialize_secret()))
    } else {
        Ok(None)
    }
}

/// # Errors
/// `Error::BadPrivate` returned if `private` is invalid.
/// `Error::BadTweak` returned if `tweak` is invalid.
pub fn private_sub(
    private: &PrivkeySlice,
    tweak: &TweakSlice,
) -> InvalidInputResult<Option<PrivkeySlice>> {
    validate_tweak(tweak)?;
    // If tweak is 0, x - 0 = x. Also, SecretKey::from_slice will error
    // if we try to use 0.
    if tweak == &ZERO32 {
        return Ok(Some(*private));
    }
    let mut sec = SecretKey::from_slice(private.as_slice()).map_err(|_| Error::BadPrivate)?;

    // We now know tweak is a valid SecretKey (validate_tweak checks < N, guard clause above checks 0)
    let mut tweak = SecretKey::from_slice(tweak.as_slice()).map_err(|_| Error::BadPrivate)?;
    tweak.negate_assign();

    if sec.add_assign(tweak.serialize_secret().as_slice()).is_ok() {
        Ok(Some(sec.serialize_secret()))
    } else {
        Ok(None)
    }
}

/// # Errors
/// `Error::BadPrivate` returned if `private` is invalid.
pub fn private_negate(private: &PrivkeySlice) -> InvalidInputResult<PrivkeySlice> {
    let mut sec = SecretKey::from_slice(private.as_slice()).map_err(|_| Error::BadPrivate)?;
    sec.negate_assign();
    Ok(sec.serialize_secret())
}

/// # Errors
/// `Error::BadHash` returned if `hash` is invalid.
/// `Error::BadPrivate` returned if `private` is invalid.
pub fn sign(
    hash: &HashSlice,
    private: &PrivkeySlice,
    extra_data: Option<&ExtraDataSlice>,
) -> InvalidInputResult<SignatureSlice> {
    let sec = SecretKey::from_slice(private.as_slice()).map_err(|_| Error::BadPrivate)?;
    let msg = Message::from_slice(hash.as_slice()).map_err(|_| Error::BadHash)?;
    let secp = get_hcontext();
    let sig = secp.sign_ecdsa(&msg, &sec);
    Ok(sig.serialize_compact())
}

/// # Errors
/// `Error::BadHash` returned if `hash` is invalid.
/// `Error::BadPrivate` returned if `private` is invalid.
pub fn sign_recoverable(
    hash: &HashSlice,
    private: &PrivkeySlice,
    extra_data: Option<&ExtraDataSlice>,
) -> InvalidInputResult<(RecoveryId, SignatureSlice)> {
    let sec = SecretKey::from_slice(private.as_slice()).map_err(|_| Error::BadPrivate)?;
    let msg = Message::from_slice(hash.as_slice()).map_err(|_| Error::BadHash)?;
    let secp = get_hcontext();
    let sig = secp.sign_ecdsa_recoverable(&msg, &sec);
    Ok(sig.serialize_compact())
}

/// # Errors
/// `Error::BadHash` returned if `hash` is invalid.
/// `Error::BadSignature` returned if `sig` is invalid.
/// `Error::BadRecoveryId` returned if `recovery_id` is invalid.
pub fn recover(
    hash: &HashSlice,
    sig: &SignatureSlice,
    recovery_id: RecoveryId,
    compressed: Option<bool>,
) -> InvalidInputResult<Pubkey> {
    let outputlen = assume_compression(compressed, None);
    // Check that the r value is less than P - N when 2nd bit is set
    if recovery_id.to_i32() & 2 == 2 && &sig[..32] >= &P_MINUS_N {
        return Err(Error::BadRecoveryId);
    }
    let msg = Message::from_slice(hash.as_slice()).map_err(|_| Error::BadHash)?;
    let sig = RecoverableSignature::from_compact(sig.as_slice(), recovery_id)
        .map_err(|_| Error::BadSignature)?;

    let secp = get_hcontext();
    let pubkey = secp
        .recover_ecdsa(&msg, &sig)
        .map_err(|_| Error::BadSignature)?;
    Ok(if outputlen == 33 {
        Pubkey::Compressed(pubkey.serialize())
    } else {
        Pubkey::Uncompressed(pubkey.serialize_uncompressed())
    })
}

/// # Errors
/// `Error::BadHash` returned if hash is invalid.
/// `Error::BadPrivate` returned if private is invalid.
pub fn sign_schnorr(
    hash: &HashSlice,
    private: &PrivkeySlice,
    extra_data: Option<&ExtraDataSlice>,
) -> InvalidInputResult<SignatureSlice> {
    let secp = get_hcontext();
    let kp = KeyPair::from_seckey_slice(secp, private).map_err(|_| Error::BadPrivate)?;
    let msg = Message::from_slice(hash).map_err(|_| Error::BadHash)?;
    let nonce = extra_data.map_or(&ZERO32, |v| v);
    let sig = secp.sign_schnorr_with_aux_rand(&msg, &kp, nonce);
    Ok(*sig.as_ref())
}

/// # Errors
/// `Error::BadHash` returned if hash is invalid.
/// `Error::BadPoint` returned if pubkey is invalid.
/// `Error::BadSignature` returned if sig is invalid.
pub fn verify(
    hash: &HashSlice,
    pubkey: &PubkeyRef,
    sig: &SignatureSlice,
    strict: Option<bool>,
) -> InvalidInputResult<bool> {
    let pb = PublicKey::from_slice(pubkey.as_slice()).map_err(|_| Error::BadPoint)?;
    let msg = Message::from_slice(hash.as_slice()).map_err(|_| Error::BadHash)?;
    let mut sg = Signature::from_compact(sig.as_slice()).map_err(|_| Error::BadSignature)?;

    let secp = get_hcontext();

    if !strict.unwrap_or(false) {
        sg.normalize_s();
    }

    Ok(secp.verify_ecdsa(&msg, &sg, &pb).is_ok())
}

/// # Errors
/// `Error::BadHash` returned if hash is invalid.
/// `Error::BadPoint` returned if pubkey is invalid.
/// `Error::BadSignature` returned if signature is invalid.
pub fn verify_schnorr(
    hash: &HashSlice,
    pubkey: &XOnlyPubkeySlice,
    signature: &SignatureSlice,
) -> InvalidInputResult<bool> {
    let pb = XOnlyPublicKey::from_slice(pubkey.as_slice()).map_err(|_| Error::BadPoint)?;
    let msg = Message::from_slice(hash.as_slice()).map_err(|_| Error::BadHash)?;
    let sg =
        schnorr::Signature::from_slice(signature.as_slice()).map_err(|_| Error::BadSignature)?;

    let secp = get_hcontext();

    Ok(secp.verify_schnorr(&sg, &msg, &pb).is_ok())
}
