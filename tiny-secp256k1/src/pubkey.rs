#[derive(Debug)]
pub enum PubkeyRef<'a> {
    XOnly(&'a [u8; 32]),
    Compressed(&'a [u8; 33]),
    Uncompressed(&'a [u8; 65]),
}

#[derive(Debug)]
pub enum Pubkey {
    XOnly([u8; 32]),
    Compressed([u8; 33]),
    Uncompressed([u8; 65]),
}

impl Pubkey {
    #[allow(clippy::missing_panics_doc)]
    pub fn new_from_len(size: usize) -> Self {
        match size {
            32 => Self::XOnly([0_u8; 32]),
            33 => Self::Compressed([0_u8; 33]),
            65 => Self::Uncompressed([0_u8; 65]),
            _ => panic!("invalid length"),
        }
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        match self {
            Self::XOnly(v) => v.as_mut_ptr(),
            Self::Compressed(v) => v.as_mut_ptr(),
            Self::Uncompressed(v) => v.as_mut_ptr(),
        }
    }
}

macro_rules! impl_pubkey {
    ($name:ident, $( $lt:tt )?) => {
        impl$(<$lt>)? $name$(<$lt>)? {
            #[allow(clippy::len_without_is_empty)]
            pub fn len(&self) -> usize {
                match self {
                    Self::XOnly(_) => 32,
                    Self::Compressed(_) => 33,
                    Self::Uncompressed(_) => 65,
                }
            }

            pub fn as_ptr(&self) -> *const u8 {
                match self {
                    Self::XOnly(v) => v.as_ptr(),
                    Self::Compressed(v) => v.as_ptr(),
                    Self::Uncompressed(v) => v.as_ptr(),
                }
            }

            pub fn as_slice(&self) -> &[u8] {
                match self {
                    Self::XOnly(v) => &v[..],
                    Self::Compressed(v) => &v[..],
                    Self::Uncompressed(v) => &v[..],
                }
            }
        }
    };
}

macro_rules! impl_pubkey_from {
    ($type:ty, $name:ident, $variant:ident, $( $lt:tt )?) => {
        impl$(<$lt>)? From<$type> for $name$(<$lt>)? {
            fn from(v: $type) -> Self {
                Self::$variant(v)
            }
        }
    };
}

impl_pubkey!(PubkeyRef, 'a);
impl_pubkey!(Pubkey,);
impl_pubkey_from!(&'a [u8; 32], PubkeyRef, XOnly, 'a);
impl_pubkey_from!(&'a [u8; 33], PubkeyRef, Compressed, 'a);
impl_pubkey_from!(&'a [u8; 65], PubkeyRef, Uncompressed, 'a);
impl_pubkey_from!([u8; 32], Pubkey, XOnly,);
impl_pubkey_from!([u8; 33], Pubkey, Compressed,);
impl_pubkey_from!([u8; 65], Pubkey, Uncompressed,);
