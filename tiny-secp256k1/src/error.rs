#[cfg(not(feature = "minimal_validation"))]
use core::fmt;

#[derive(Debug)]
#[repr(usize)]
pub enum Error {
    BadPrivate = 0_usize,
    BadPoint,
    BadTweak,
    BadHash,
    BadSignature,
    BadExtraData,
    BadParity,
    BadRecoveryId,
}

#[cfg(not(feature = "minimal_validation"))]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::BadPrivate => f.write_str("Expected Private"),
            Self::BadPoint => f.write_str("Expected Point"),
            Self::BadTweak => f.write_str("Expected Tweak"),
            Self::BadHash => f.write_str("Expected Hash"),
            Self::BadSignature => f.write_str("Expected Signature"),
            Self::BadExtraData => f.write_str("Expected Extra Data (32 bytes)"),
            Self::BadParity => f.write_str("Expected Parity (1 | 0)"),
            Self::BadRecoveryId => f.write_str("Bad Recovery Id"),
        }
    }
}
