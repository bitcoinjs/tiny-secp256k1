pub(crate) const PRIVATE_KEY_SIZE: usize = 32;
pub(crate) const PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;
pub(crate) const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
pub(crate) const X_ONLY_PUBLIC_KEY_SIZE: usize = 32;
pub(crate) const TWEAK_SIZE: usize = 32;
pub(crate) const HASH_SIZE: usize = 32;
pub(crate) const EXTRA_DATA_SIZE: usize = 32;
pub(crate) const SIGNATURE_SIZE: usize = 64;

pub(crate) const ZERO32: [u8; 32] = [0_u8; 32];
pub(crate) const ORDER: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220,
    230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
];
