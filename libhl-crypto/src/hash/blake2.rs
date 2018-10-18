use super::Digest;
use CryptoError;
use blake2b_simd::{Params, State};

macro_rules! impl_hasher {
    ($thing:ident,$size:tt) => {
        impl Digest for $thing {
            #[inline]
            fn new() -> $thing {
                $thing(Params::new()
                       .hash_length($size)
                       .to_state())
            }
            #[inline]
            fn reset(&mut self) {
                self.0 = Params::new()
                         .hash_length($size)
                         .to_state();
            }
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }
            #[inline]
            fn finalize(&mut self) -> Result<Vec<u8>, CryptoError> {
                Ok(self.0.finalize().as_bytes().to_vec())
            }
        }
    };
}

pub struct Blake2b256(State);
impl_hasher!(Blake2b256, 32);

pub struct Blake2b384(State);
impl_hasher!(Blake2b384, 48);

pub struct Blake2b512(State);
impl_hasher!(Blake2b512, 64);

//#[cfg(all(feature = "native", not(feature = "portable")))]
//mod blake2b_hash {
//    use super::*;
//    use libsodium_ffi as ffi;
//    use std::mem;
//    use std::ptr;
//
//    pub struct Blake2b {
//        state: ffi::crypto_generichash_blake2b_state,
//        size: usize
//    }
//
//    impl Blake2b {
//        pub fn new(size: usize) -> Blake2b {
//            let mut state: ffi::crypto_generichash_blake2b_state;
//            unsafe {
//                state = mem::uninitialized();
//                ffi::crypto_generichash_init(&mut state, ptr::null(), 0, size)
//            };
//            Blake2b {
//                state,
//                size
//            }
//        }
//
//        pub fn reset(&mut self) {
//            unsafe {
//                self.state = mem::uninitialized();
//                ffi::crypto_generichash_init(&mut self.state, ptr::null(), 0, self.size)
//            };
//        }
//
//        pub fn update(&mut self, data: &[u8]) {
//            unsafe {
//                ffi::crypto_generichash_update(
//                    &mut self.state,
//                    data.as_ptr(),
//                    data.len() as u64,
//                )
//            };
//        }
//
//        pub fn finalize(&mut self) -> Result<Vec<u8>, CryptoError> {
//            let mut data = [0u8; ffi::crypto_generichash_BYTES_MAX as usize];
//            let rc = unsafe {
//                ffi::crypto_generichash_final(
//                    &mut self.state,
//                    data.as_mut_ptr(),
//                    self.size,
//                )
//            };
//            self.reset();
//            if rc == 0 {
//                Ok(data[0..self.size].to_vec())
//            } else {
//                Err(CryptoError::DigestGenError("An error occurred while hashing".to_string()))
//            }
//        }
//    }
//}
//
//#[cfg(all(feature = "portable", not(feature = "native")))]
//mod blake2b_hash {
//    use super::*;
//    use rcrypto;
//    use rcrypto::mac::Mac;
//
//    pub struct Blake2b(rcrypto::blake2b::Blake2b);
//
//    impl Blake2b {
//        pub fn new(size: usize) -> Blake2b {
//            Blake2b(rcrypto::blake2b::Blake2b::new(size))
//        }
//
//        pub fn reset(&mut self) {
//            self.0.reset()
//        }
//
//        pub fn update(&mut self, data: &[u8]) {
//            self.0.input(data)
//        }
//
//        pub fn finalize(&mut self) -> Result<Vec<u8>, CryptoError> {
//            let mut data = [0u8; self.0.output_bytes];
//            self.0.result(&mut data);
//            Ok(data.to_vec())
//        }
//    }
//}
//
//#[cfg(test)]
//mod tests {
//
//    #[test]
//    fn test_vectors() {
//
//    }
//}
