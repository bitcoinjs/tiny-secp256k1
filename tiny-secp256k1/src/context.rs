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
            set_context(simple_rand::get_rand())
        }
    }
}

// Simple random seed generator.
// Only for randomizing context when no seed it provided.
#[cfg(not(feature = "rand"))]
mod simple_rand {
    struct Xorshift128(u32, u32, u32, u32);
    impl Xorshift128 {
        fn new(seed: u32) -> Self {
            // Initial state is first 128 bits of
            // secp256k1 generator point x value
            Xorshift128(
                0x79BE667E ^ seed,
                0xF9DCBBAC ^ seed.wrapping_shl(13),
                0x55A06295 ^ seed.wrapping_shr(7),
                0xCE870B07 ^ seed.wrapping_shl(5),
            )
        }
        fn next_32bytes(&mut self) -> [u8; 32] {
            let ret = [0_u32; 8].map(|_| self.next_u32());
            // We know this is safe
            unsafe { core::mem::transmute::<[u32; 8], [u8; 32]>(ret) }
        }

        fn next_u32(&mut self) -> u32 {
            /* Algorithm "xor128" from p. 5 of Marsaglia, "Xorshift RNGs" */
            let mut t = self.3;

            let s = self.0; /* Perform a contrived 32-bit shift. */
            self.3 = self.2;
            self.2 = self.1;
            self.1 = s;

            t ^= t.wrapping_shl(11);
            t ^= t.wrapping_shr(8);
            self.0 = t ^ s ^ s.wrapping_shr(19);
            self.0
        }
    }

    static mut USED: bool = false;
    pub fn get_rand() -> [u8; 32] {
        if unsafe { USED } {
            panic!("Only use get_rand once!");
        }
        // xorshift128 seeded with ptr of a new stack variable
        let ptr = (&[0u8; 4]).as_ptr() as u32;
        let ret = Xorshift128::new(ptr).next_32bytes();
        unsafe {
            USED = true;
        };
        ret
    }
}
