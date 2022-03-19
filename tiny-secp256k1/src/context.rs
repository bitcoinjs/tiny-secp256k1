#[cfg(feature = "rand")]
use rand::{self, RngCore};

#[allow(clippy::large_stack_arrays)]
mod globals {
    pub use core::mem::transmute;
    pub use secp256k1::{
        ffi::{types::AlignedType, Context},
        AllPreallocated, Secp256k1,
    };

    #[cfg(target_pointer_width = "32")]
    pub mod ptr_width_params {
        use super::{transmute, AlignedType};
        pub const ALIGN_SIZE: usize = 69_645;
        pub static mut CONTEXT_BUFFER: [AlignedType; ALIGN_SIZE] =
            unsafe { transmute([0_u8; ALIGN_SIZE * 16]) };
    }
    #[cfg(target_pointer_width = "64")]
    pub mod ptr_width_params {
        use super::{transmute, AlignedType};
        pub const ALIGN_SIZE: usize = 69_646;
        pub static mut CONTEXT_BUFFER: [AlignedType; ALIGN_SIZE] =
            unsafe { transmute([0_u8; ALIGN_SIZE * 16]) };
    }

    pub static mut SECP256K1: Option<Secp256k1<AllPreallocated>> = None;
}
use globals::{ptr_width_params::CONTEXT_BUFFER, AllPreallocated, Secp256k1, SECP256K1};

#[allow(clippy::missing_panics_doc)]
pub fn set_context(seed: &[u8; 32]) -> &'static Secp256k1<AllPreallocated<'static>> {
    unsafe {
        if SECP256K1.is_none() {
            SECP256K1 = Some(
                Secp256k1::preallocated_new(&mut CONTEXT_BUFFER)
                    .expect("CONTEXT_BUFFER length incorrect for this target"),
            );
        }
        SECP256K1.as_mut().unwrap().seeded_randomize(seed);
        SECP256K1.as_ref().unwrap()
    }
}

pub(crate) fn get_hcontext() -> &'static Secp256k1<AllPreallocated<'static>> {
    unsafe {
        if SECP256K1.is_some() {
            SECP256K1.as_ref().unwrap()
        } else {
            #[cfg(feature = "rand")]
            {
                let mut seed = [0_u8; 32];
                rand::thread_rng().fill_bytes(&mut seed);
                set_context(&seed)
            }
            #[cfg(not(feature = "rand"))]
            {
                set_context(&simple_rand::get_rand())
            }
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
                0x79BE_667E ^ seed,
                0xF9DC_BBAC ^ seed.wrapping_shl(13),
                0x55A0_6295 ^ seed.wrapping_shr(7),
                0xCE87_0B07 ^ seed.wrapping_shl(5),
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
    pub(crate) fn get_rand() -> [u8; 32] {
        // This function returns the same value
        // everytime it's called on the same run.
        // However, each run should produce a different
        // value, so it is suitable (better than not randomizing)
        // for the one time initialization of context.
        if unsafe { USED } {
            panic!("Only use get_rand once!");
        }
        // xorshift128 seeded with ptr of a new stack variable
        let ptr = (&[0_u8; 4]).as_ptr() as u32;
        let ret = Xorshift128::new(ptr).next_32bytes();
        unsafe {
            USED = true;
        };
        ret
    }
}
