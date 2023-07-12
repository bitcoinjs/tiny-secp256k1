macro_rules! jstry {
    ($value:expr) => {
        jstry!($value, ())
    };
    ($value:expr, $ret:expr) => {
        match $value {
            Ok(value) => value,
            Err(code) => {
                throw_error(code as usize);
                return $ret;
            }
        }
    };
}

macro_rules! jstry_opt {
    ($value:expr, $ret:expr) => {
        match $value {
            Ok(value) => {
                if let Some(v) = value {
                    v
                } else {
                    return $ret;
                }
            }
            Err(code) => {
                throw_error(code as usize);
                return $ret;
            }
        }
    };
}

macro_rules! pubkey_size_to_opt_bool {
    ($value:expr) => {
        match $value {
            65 => Some(false),
            33 => Some(true),
            _ => None,
        }
    };
}

macro_rules! parity_to_opt_int {
    ($value:expr) => {
        match $value {
            0 => Some(0),
            1 => Some(1),
            _ => None,
        }
    };
}

macro_rules! priv_or_ret {
    ($private:expr, $ret:expr) => {
        match $private {
            Some(prv) => prv,
            None => {
                return $ret;
            }
        }
    };
}

macro_rules! bad_point {
    () => {
        unsafe {
            throw_error(tiny_secp256k1::Error::BadPoint as usize);
        }
        panic!("Bad Point");
    };
}
