#[cfg(feature = "rand")]
use rand::{self, RngCore};

use secp256k1_sys::{
    secp256k1_context_preallocated_create, secp256k1_context_preallocated_size,
    secp256k1_context_randomize, types::c_void, Context, SECP256K1_START_SIGN,
    SECP256K1_START_VERIFY,
};

#[allow(clippy::large_stack_arrays)]
mod buffers {
    use secp256k1_sys::Context;

    #[cfg(target_pointer_width = "32")]
    pub(crate) static CONTEXT_BUFFER: [u8; 1_114_320] = [0; 1_114_320];
    #[cfg(target_pointer_width = "64")]
    pub(crate) static CONTEXT_BUFFER: [u8; 1_114_336] = [0; 1_114_336];

    pub(crate) static mut CONTEXT: *const Context = core::ptr::null();
    pub(crate) static mut CONTEXT_SET: bool = false;
}
use buffers::{CONTEXT, CONTEXT_BUFFER, CONTEXT_SET};

#[allow(clippy::missing_panics_doc)]
#[cfg(feature = "no_std")]
pub fn set_context(seed: [u8; 32]) -> *const Context {
    unsafe {
        let size =
            secp256k1_context_preallocated_size(SECP256K1_START_SIGN | SECP256K1_START_VERIFY);
        assert_eq!(size, CONTEXT_BUFFER.len());
        let ctx = secp256k1_context_preallocated_create(
            CONTEXT_BUFFER.as_ptr() as *mut c_void,
            SECP256K1_START_SIGN | SECP256K1_START_VERIFY,
        );
        let retcode = secp256k1_context_randomize(ctx, seed.as_ptr());
        assert_eq!(retcode, 1);
        CONTEXT = ctx;
        CONTEXT_SET = true;
        CONTEXT
    }
}

#[cfg(not(feature = "no_std"))]
#[allow(clippy::missing_panics_doc)]
pub fn set_context(seed: [u8; 32]) -> *const Context {
    unsafe {
        let flags = SECP256K1_START_SIGN | SECP256K1_START_VERIFY;
        let size = secp256k1_context_preallocated_size(flags);
        assert_eq!(size, CONTEXT_BUFFER.len());
        let layout = std::alloc::Layout::from_size_align(size, 16).unwrap();
        let ptr = std::alloc::alloc(layout);
        let ctx = secp256k1_context_preallocated_create(ptr as *mut c_void, flags);
        let retcode = secp256k1_context_randomize(ctx, seed.as_ptr());
        assert_eq!(retcode, 1);
        CONTEXT = ctx;
        CONTEXT_SET = true;
        CONTEXT
    }
}

pub(crate) fn get_context() -> *const Context {
    unsafe {
        if CONTEXT_SET {
            CONTEXT
        } else {
            #[cfg(feature = "rand")]
            {
                let mut seed = [0_u8; 32];
                rand::thread_rng().fill_bytes(&mut seed);
                set_context(seed)
            }
            #[cfg(not(feature = "rand"))]
            panic!("No context");
        }
    }
}
