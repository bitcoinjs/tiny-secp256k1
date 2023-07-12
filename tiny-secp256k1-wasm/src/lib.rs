#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![no_std]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("Only `wasm32` target_arch is supported.");

#[panic_handler]
#[cfg(target_arch = "wasm32")]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[macro_use]
mod macros;
mod into_pubkey;
use core::cell::UnsafeCell;
use into_pubkey::GeneralKey;

#[link(wasm_import_module = "./validate_error.js")]
extern "C" {
    #[link_name = "throwError"]
    fn throw_error(errcode: usize);
}

#[link(wasm_import_module = "./rand.js")]
extern "C" {
    #[link_name = "generateInt32"]
    fn generate_int32() -> i32;
}

pub struct UCWrapper<T: Sync + Copy>(pub(crate) UnsafeCell<T>);
unsafe impl<T: Sync + Copy> Sync for UCWrapper<T> {}
impl<T: Sync + Copy> UCWrapper<T> {
    unsafe fn get_ref(&self) -> &T {
        self.0.get().as_ref().unwrap()
    }
    #[allow(clippy::mut_from_ref)]
    unsafe fn get_mut(&self) -> &mut T {
        self.0.get().as_mut().unwrap()
    }
    // If needed in the future
    // unsafe fn get_copy(&self) -> T {
    //     *self.0.get().as_mut().unwrap()
    // }
}

const PRIVATE_KEY_SIZE: usize = 32;
const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
const X_ONLY_PUBLIC_KEY_SIZE: usize = 32;
const TWEAK_SIZE: usize = 32;
const HASH_SIZE: usize = 32;
const EXTRA_DATA_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;

#[no_mangle]
pub static PRIVATE_INPUT: UCWrapper<[u8; PRIVATE_KEY_SIZE]> =
    UCWrapper(UnsafeCell::new([0; PRIVATE_KEY_SIZE]));
#[no_mangle]
pub static PUBLIC_KEY_INPUT: UCWrapper<[u8; PUBLIC_KEY_UNCOMPRESSED_SIZE]> =
    UCWrapper(UnsafeCell::new([0; PUBLIC_KEY_UNCOMPRESSED_SIZE]));
#[no_mangle]
pub static PUBLIC_KEY_INPUT2: UCWrapper<[u8; PUBLIC_KEY_UNCOMPRESSED_SIZE]> =
    UCWrapper(UnsafeCell::new([0; PUBLIC_KEY_UNCOMPRESSED_SIZE]));
#[no_mangle]
pub static X_ONLY_PUBLIC_KEY_INPUT: UCWrapper<[u8; X_ONLY_PUBLIC_KEY_SIZE]> =
    UCWrapper(UnsafeCell::new([0; X_ONLY_PUBLIC_KEY_SIZE]));
#[no_mangle]
pub static X_ONLY_PUBLIC_KEY_INPUT2: UCWrapper<[u8; X_ONLY_PUBLIC_KEY_SIZE]> =
    UCWrapper(UnsafeCell::new([0; X_ONLY_PUBLIC_KEY_SIZE]));
#[no_mangle]
pub static TWEAK_INPUT: UCWrapper<[u8; TWEAK_SIZE]> = UCWrapper(UnsafeCell::new([0; TWEAK_SIZE]));
#[no_mangle]
pub static HASH_INPUT: UCWrapper<[u8; HASH_SIZE]> = UCWrapper(UnsafeCell::new([0; HASH_SIZE]));
#[no_mangle]
pub static EXTRA_DATA_INPUT: UCWrapper<[u8; EXTRA_DATA_SIZE]> =
    UCWrapper(UnsafeCell::new([0; EXTRA_DATA_SIZE]));
#[no_mangle]
pub static SIGNATURE_INPUT: UCWrapper<[u8; SIGNATURE_SIZE]> =
    UCWrapper(UnsafeCell::new([0; SIGNATURE_SIZE]));

fn build_context() {
    let mut seed = [0_u8; 32];
    unsafe {
        for offset in (0..8).map(|v| v * 4) {
            let value = generate_int32();
            let bytes: [u8; 4] = value.to_ne_bytes();
            seed[offset..offset + 4].copy_from_slice(&bytes);
        }
    }
    tiny_secp256k1::set_context(&seed);
}

#[no_mangle]
#[export_name = "initializeContext"]
pub extern "C" fn initialize_context() {
    build_context();
}

#[no_mangle]
#[export_name = "isPoint"]
pub extern "C" fn is_point(inputlen: usize) -> usize {
    unsafe {
        let pubkey = GeneralKey(PUBLIC_KEY_INPUT.get_ref(), &inputlen);
        usize::from(tiny_secp256k1::is_point(&pubkey.into()))
    }
}

#[no_mangle]
#[export_name = "pointAdd"]
pub extern "C" fn point_add(inputlen: usize, inputlen2: usize, compressed: usize) -> i32 {
    unsafe {
        let pubkey = jstry_opt!(
            tiny_secp256k1::point_add(
                &GeneralKey(PUBLIC_KEY_INPUT.get_ref(), &inputlen).into(),
                &GeneralKey(PUBLIC_KEY_INPUT2.get_ref(), &inputlen2).into(),
                pubkey_size_to_opt_bool!(compressed)
            ),
            0
        );
        let size = pubkey.len();
        PUBLIC_KEY_INPUT.get_mut()[..size].copy_from_slice(&pubkey.as_slice()[..size]);
        1
    }
}

#[no_mangle]
#[export_name = "pointAddScalar"]
pub extern "C" fn point_add_scalar(inputlen: usize, compressed: usize) -> i32 {
    unsafe {
        let pubkey = jstry_opt!(
            tiny_secp256k1::point_add_scalar(
                &GeneralKey(PUBLIC_KEY_INPUT.get_ref(), &inputlen).into(),
                TWEAK_INPUT.get_ref(),
                pubkey_size_to_opt_bool!(compressed)
            ),
            0
        );
        let size = pubkey.len();
        PUBLIC_KEY_INPUT.get_mut()[..size].copy_from_slice(&pubkey.as_slice()[..size]);
        1
    }
}

#[no_mangle]
#[export_name = "xOnlyPointAddTweak"]
pub extern "C" fn x_only_point_add_tweak() -> i32 {
    unsafe {
        let (x_only_point, parity) = jstry_opt!(
            tiny_secp256k1::x_only_point_add_tweak(
                X_ONLY_PUBLIC_KEY_INPUT.get_ref(),
                TWEAK_INPUT.get_ref()
            ),
            -1
        );
        X_ONLY_PUBLIC_KEY_INPUT.get_mut()[..X_ONLY_PUBLIC_KEY_SIZE]
            .copy_from_slice(&x_only_point[..X_ONLY_PUBLIC_KEY_SIZE]);
        parity
    }
}

#[no_mangle]
#[export_name = "xOnlyPointAddTweakCheck"]
pub extern "C" fn x_only_point_add_tweak_check(tweaked_parity: i32) -> i32 {
    unsafe {
        let tweaked_parity = parity_to_opt_int!(tweaked_parity);
        i32::from(jstry!(
            tiny_secp256k1::x_only_point_add_tweak_check(
                X_ONLY_PUBLIC_KEY_INPUT.get_ref(),
                &(*X_ONLY_PUBLIC_KEY_INPUT2.get_ref(), tweaked_parity),
                TWEAK_INPUT.get_ref()
            ),
            0
        ))
    }
}

#[no_mangle]
#[export_name = "pointCompress"]
pub extern "C" fn point_compress(inputlen: usize, compressed: usize) {
    unsafe {
        let pubkey = jstry!(tiny_secp256k1::point_compress(
            &GeneralKey(PUBLIC_KEY_INPUT.get_ref(), &inputlen).into(),
            pubkey_size_to_opt_bool!(compressed)
        ));
        let size = pubkey.len();
        PUBLIC_KEY_INPUT.get_mut()[..size].copy_from_slice(&pubkey.as_slice()[..size]);
    }
}

#[no_mangle]
#[export_name = "pointFromScalar"]
pub extern "C" fn point_from_scalar(compressed: usize) -> i32 {
    unsafe {
        let pubkey = jstry_opt!(
            tiny_secp256k1::point_from_scalar(
                PRIVATE_INPUT.get_ref(),
                pubkey_size_to_opt_bool!(compressed)
            ),
            0
        );
        let size = pubkey.len();
        PUBLIC_KEY_INPUT.get_mut()[..size].copy_from_slice(&pubkey.as_slice()[..size]);
        1
    }
}

#[no_mangle]
#[export_name = "xOnlyPointFromScalar"]
pub extern "C" fn x_only_point_from_scalar() {
    unsafe {
        let (point, _parity) = tiny_secp256k1::x_only_point_from_scalar(PRIVATE_INPUT.get_ref())
            .expect("JS side validation");
        X_ONLY_PUBLIC_KEY_INPUT.get_mut().copy_from_slice(&point);
    }
}

#[no_mangle]
#[export_name = "xOnlyPointFromPoint"]
pub extern "C" fn x_only_point_from_point(inputlen: usize) {
    unsafe {
        let (point, _parity) = jstry!(tiny_secp256k1::x_only_point_from_point(
            &GeneralKey(PUBLIC_KEY_INPUT.get_ref(), &inputlen).into()
        ));
        X_ONLY_PUBLIC_KEY_INPUT.get_mut().copy_from_slice(&point);
    }
}

#[no_mangle]
#[export_name = "pointMultiply"]
pub extern "C" fn point_multiply(inputlen: usize, compressed: usize) -> i32 {
    unsafe {
        let pubkey = jstry_opt!(
            tiny_secp256k1::point_multiply(
                &GeneralKey(PUBLIC_KEY_INPUT.get_ref(), &inputlen).into(),
                TWEAK_INPUT.get_ref(),
                pubkey_size_to_opt_bool!(compressed)
            ),
            0
        );
        let size = pubkey.len();
        PUBLIC_KEY_INPUT.get_mut()[..size].copy_from_slice(&pubkey.as_slice()[..size]);
        1
    }
}

#[no_mangle]
#[export_name = "privateAdd"]
pub extern "C" fn private_add() -> i32 {
    unsafe {
        let private = jstry!(
            tiny_secp256k1::private_add(PRIVATE_INPUT.get_ref(), TWEAK_INPUT.get_ref()),
            0
        );
        PRIVATE_INPUT
            .get_mut()
            .copy_from_slice(&priv_or_ret!(private, 0));
        1
    }
}

#[no_mangle]
#[export_name = "privateSub"]
pub extern "C" fn private_sub() -> i32 {
    unsafe {
        let private = jstry!(
            tiny_secp256k1::private_sub(PRIVATE_INPUT.get_ref(), TWEAK_INPUT.get_ref()),
            0
        );
        PRIVATE_INPUT
            .get_mut()
            .copy_from_slice(&priv_or_ret!(private, 0));
        1
    }
}

#[no_mangle]
#[export_name = "privateNegate"]
pub extern "C" fn private_negate() {
    unsafe {
        let private = jstry!(tiny_secp256k1::private_negate(PRIVATE_INPUT.get_ref()));
        PRIVATE_INPUT.get_mut().copy_from_slice(&private);
    }
}

#[no_mangle]
pub extern "C" fn sign(extra_data: i32) {
    unsafe {
        SIGNATURE_INPUT
            .get_mut()
            .copy_from_slice(&jstry!(tiny_secp256k1::sign(
                HASH_INPUT.get_ref(),
                PRIVATE_INPUT.get_ref(),
                if extra_data == 0 {
                    None
                } else {
                    Some(EXTRA_DATA_INPUT.get_ref())
                },
            )));
    }
}

#[no_mangle]
#[export_name = "signRecoverable"]
pub extern "C" fn sign_recoverable(extra_data: i32) -> i32 {
    unsafe {
        let sig = jstry!(
            tiny_secp256k1::sign_recoverable(
                HASH_INPUT.get_ref(),
                PRIVATE_INPUT.get_ref(),
                if extra_data == 0 {
                    None
                } else {
                    Some(EXTRA_DATA_INPUT.get_ref())
                },
            ),
            0
        );
        SIGNATURE_INPUT.get_mut().copy_from_slice(&sig.1);
        sig.0.to_i32()
    }
}

#[no_mangle]
#[export_name = "signSchnorr"]
pub extern "C" fn sign_schnorr(extra_data: i32) {
    unsafe {
        SIGNATURE_INPUT
            .get_mut()
            .copy_from_slice(&jstry!(tiny_secp256k1::sign_schnorr(
                HASH_INPUT.get_ref(),
                PRIVATE_INPUT.get_ref(),
                if extra_data == 0 {
                    None
                } else {
                    Some(EXTRA_DATA_INPUT.get_ref())
                },
            )));
    }
}

#[no_mangle]
pub extern "C" fn verify(inputlen: usize, strict: i32) -> i32 {
    unsafe {
        i32::from(jstry!(
            tiny_secp256k1::verify(
                HASH_INPUT.get_ref(),
                &GeneralKey(PUBLIC_KEY_INPUT.get_ref(), &inputlen).into(),
                SIGNATURE_INPUT.get_ref(),
                match strict {
                    1 => Some(true),
                    0 => Some(false),
                    _ => None,
                }
            ),
            0
        ))
    }
}

#[allow(clippy::missing_panics_doc)]
#[no_mangle]
pub extern "C" fn recover(outputlen: usize, recid: i32) -> i32 {
    unsafe {
        let pubkey = jstry!(
            tiny_secp256k1::recover(
                HASH_INPUT.get_ref(),
                SIGNATURE_INPUT.get_ref(),
                tiny_secp256k1::RecoveryId::from_i32(recid).unwrap(),
                pubkey_size_to_opt_bool!(outputlen),
            ),
            0
        );
        let size = pubkey.len();
        PUBLIC_KEY_INPUT.get_mut()[..size].copy_from_slice(&pubkey.as_slice()[..size]);
        1
    }
}

#[no_mangle]
#[export_name = "verifySchnorr"]
pub extern "C" fn verify_schnorr() -> i32 {
    unsafe {
        i32::from(jstry!(
            tiny_secp256k1::verify_schnorr(
                HASH_INPUT.get_ref(),
                X_ONLY_PUBLIC_KEY_INPUT.get_ref(),
                SIGNATURE_INPUT.get_ref()
            ),
            0
        ))
    }
}
