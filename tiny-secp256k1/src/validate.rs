use super::{
    consts::{
        PUBLIC_KEY_COMPRESSED_SIZE, PUBLIC_KEY_UNCOMPRESSED_SIZE, X_ONLY_PUBLIC_KEY_SIZE, ZERO32,
    },
    error::Error,
    types::{InvalidInputResult, PrivkeySlice, PubkeySlice, SignatureSlice, TweakSlice},
};

pub(crate) const ORDER: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220,
    230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
];

// pub(crate) fn is_zero(v: &[u8; 32]) -> bool {
//     v == &ZERO32
// }

pub(crate) fn is_private(v: &PrivkeySlice) -> bool {
    v > &ZERO32 && v < &ORDER
}

pub(crate) fn is_point(v: &PubkeySlice) -> bool {
    v.1 == PUBLIC_KEY_COMPRESSED_SIZE
        || v.1 == PUBLIC_KEY_UNCOMPRESSED_SIZE
        || v.1 == X_ONLY_PUBLIC_KEY_SIZE
}

// pub(crate) fn is_der_point(v: &PubkeySlice) -> bool {
//     v.1 == PUBLIC_KEY_COMPRESSED_SIZE || v.1 == PUBLIC_KEY_UNCOMPRESSED_SIZE
// }

// pub(crate) fn is_point_compressed(v: &PubkeySlice) -> bool {
//     v.1 == PUBLIC_KEY_COMPRESSED_SIZE
// }

pub(crate) fn is_tweak(v: &TweakSlice) -> bool {
    v < &ORDER
}

pub(crate) fn is_signature(v: &SignatureSlice) -> bool {
    // guarantee size of array
    let _: &[u8; 64] = v;
    unsafe {
        let r = v.as_ptr().cast::<[u8; 32]>().as_ref().unwrap();
        let s = v.as_ptr().offset(32).cast::<[u8; 32]>().as_ref().unwrap();
        is_tweak(r) && is_tweak(s)
    }
}

pub(crate) fn validate_parity(p: i32) -> InvalidInputResult<()> {
    if p != 0 && p != 1 {
        Err(Error::BadParity)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_private(p: &PrivkeySlice) -> InvalidInputResult<()> {
    if is_private(p) {
        Ok(())
    } else {
        Err(Error::BadPrivate)
    }
}

pub(crate) fn validate_point(p: &PubkeySlice) -> InvalidInputResult<()> {
    if is_point(p) {
        Ok(())
    } else {
        Err(Error::BadPoint)
    }
}

pub(crate) fn validate_tweak(p: &TweakSlice) -> InvalidInputResult<()> {
    if is_tweak(p) {
        Ok(())
    } else {
        Err(Error::BadTweak)
    }
}

pub(crate) fn validate_signature(p: &SignatureSlice) -> InvalidInputResult<()> {
    if is_signature(p) {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}
