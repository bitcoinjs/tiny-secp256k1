pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;
pub const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
pub const X_ONLY_PUBLIC_KEY_SIZE: usize = 32;
pub const TWEAK_SIZE: usize = 32;
pub const HASH_SIZE: usize = 32;
pub const EXTRA_DATA_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

pub const ZERO32: [u8; 32] = [0_u8; 32];
pub const ORDER: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220,
    230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
];
pub const P_MINUS_N: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 69, 81, 35, 25, 80, 183, 95, 196, 64, 45, 161,
    114, 47, 201, 186, 238,
];
