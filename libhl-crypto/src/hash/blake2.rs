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
