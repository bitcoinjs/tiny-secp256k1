pub use super::{
    consts::{
        EXTRA_DATA_SIZE, HASH_SIZE, PRIVATE_KEY_SIZE, SIGNATURE_SIZE, TWEAK_SIZE,
        X_ONLY_PUBLIC_KEY_SIZE,
    },
    error::Error,
};

pub type InvalidInputResult<T> = Result<T, Error>;

pub type PrivkeySlice = [u8; PRIVATE_KEY_SIZE];
pub type XOnlyPubkeySlice = [u8; X_ONLY_PUBLIC_KEY_SIZE];
pub type XOnlyPubkeyWithMaybeParity = (XOnlyPubkeySlice, Option<i32>);
pub type XOnlyPubkeyWithParity = (XOnlyPubkeySlice, i32);
pub type TweakSlice = [u8; TWEAK_SIZE];
pub type HashSlice = [u8; HASH_SIZE];
pub type ExtraDataSlice = [u8; EXTRA_DATA_SIZE];
pub type SignatureSlice = [u8; SIGNATURE_SIZE];
