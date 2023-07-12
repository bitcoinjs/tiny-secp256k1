use super::throw_error;
// const ZERO32: [u8; 32] = [0_u8; 32];
pub(crate) struct GeneralKey<'a>(pub(crate) &'a [u8; 65], pub(crate) &'a usize);

impl<'a> From<GeneralKey<'a>> for tiny_secp256k1::Pubkey {
    fn from(v: GeneralKey<'a>) -> tiny_secp256k1::Pubkey {
        match v.1 {
            65 => {
                // if v.0[0] != 4_u8 {
                //     bad_point!();
                // }
                tiny_secp256k1::Pubkey::Uncompressed(*v.0)
            }
            33 => {
                // if (v.0[0] != 2_u8 && v.0[0] != 3_u8) || v.0[33..65] != ZERO32 {
                //     bad_point!();
                // }
                tiny_secp256k1::Pubkey::Compressed(unsafe {
                    *v.0.as_ptr().cast::<[u8; 33]>().as_ref().unwrap()
                })
            }
            32 => {
                // if v.0[32] != 0_u8 || v.0[33..65] != ZERO32 {
                //     bad_point!();
                // }
                tiny_secp256k1::Pubkey::XOnly(unsafe {
                    *v.0.as_ptr().cast::<[u8; 32]>().as_ref().unwrap()
                })
            }
            _ => {
                bad_point!();
            }
        }
    }
}

impl<'a> From<GeneralKey<'a>> for tiny_secp256k1::PubkeyRef<'a> {
    fn from(v: GeneralKey<'a>) -> tiny_secp256k1::PubkeyRef<'a> {
        match v.1 {
            65 => {
                // if v.0[0] != 4_u8 {
                //     bad_point!();
                // }
                tiny_secp256k1::PubkeyRef::Uncompressed(v.0)
            }
            33 => {
                // if (v.0[0] != 2_u8 && v.0[0] != 3_u8) || v.0[33..65] != ZERO32 {
                //     bad_point!();
                // }
                tiny_secp256k1::PubkeyRef::Compressed(unsafe {
                    v.0.as_ptr().cast::<[u8; 33]>().as_ref().unwrap()
                })
            }
            32 => {
                // if v.0[32] != 0_u8 || v.0[33..65] != ZERO32 {
                //     bad_point!();
                // }
                tiny_secp256k1::PubkeyRef::XOnly(unsafe {
                    v.0.as_ptr().cast::<[u8; 32]>().as_ref().unwrap()
                })
            }
            _ => {
                bad_point!();
            }
        }
    }
}
