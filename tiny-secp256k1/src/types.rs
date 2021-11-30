pub(crate) use super::{
    consts::{
        EXTRA_DATA_SIZE, HASH_SIZE, PRIVATE_KEY_SIZE, SIGNATURE_SIZE, TWEAK_SIZE,
        X_ONLY_PUBLIC_KEY_SIZE,
    },
    error::Error,
};

pub(crate) type InvalidInputResult<T> = Result<T, Error>;

pub(crate) type PrivkeySlice = [u8; PRIVATE_KEY_SIZE];
pub(crate) type XOnlyPubkeySlice = [u8; X_ONLY_PUBLIC_KEY_SIZE];
pub(crate) type XOnlyPubkeyWithMaybeParity = (XOnlyPubkeySlice, Option<i32>);
pub(crate) type XOnlyPubkeyWithParity = (XOnlyPubkeySlice, i32);
pub(crate) type TweakSlice = [u8; TWEAK_SIZE];
pub(crate) type HashSlice = [u8; HASH_SIZE];
pub(crate) type ExtraDataSlice = [u8; EXTRA_DATA_SIZE];
pub(crate) type SignatureSlice = [u8; SIGNATURE_SIZE];
