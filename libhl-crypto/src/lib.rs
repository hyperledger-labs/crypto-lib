/// Portable try to solely use Rust and no external C libraries.
/// This is considered less secure only because the Rust code may not have had a
/// security audited yet.
///
/// Native uses external C libraries that have had a security audit performed

extern crate amcl;
extern crate amcl_3;
#[cfg(feature = "portable")]
#[macro_use]
extern crate arrayref;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate rand;
extern crate sha2;
extern crate sha3;
#[cfg(any(test, all(feature = "native", not(feature = "portable"))))]
extern crate libsodium_ffi;
#[cfg(any(test, all(feature = "portable", not(feature = "native"))))]
extern crate crypto as rcrypto;
#[cfg(any(test, all(feature = "native", not(feature = "portable"))))]
extern crate secp256k1 as libsecp256k1;
#[cfg(any(test, all(feature = "portable", not(feature = "native"))))]
extern crate rustlibsecp256k1;

// To use macros from util inside of other modules it must me loaded first.
#[macro_use]
pub mod utils;

#[cfg(feature = "serialization")]
extern crate serde;

#[cfg(feature = "serialization")]
#[allow(unused_imports)] // Remove false positive warning. See https://github.com/rust-lang/rust/issues/44342
#[macro_use]
extern crate serde_derive;

#[cfg(not(test))]
#[cfg(feature = "serialization")]
extern crate serde_json;

#[cfg(test)]
#[cfg(feature = "serialization")]
#[macro_use]
extern crate serde_json;

#[cfg(feature = "bn_openssl")]
extern crate openssl;

#[cfg(feature = "bn_openssl")]
extern crate int_traits;

extern crate libc;

extern crate time;

pub mod cl;
pub mod bls;

#[cfg(feature = "bn_openssl")]
#[path = "bn/openssl.rs"]
pub mod bn;

pub mod errors;
pub mod ffi;

#[cfg(feature = "pair_amcl")]
#[path = "pair/amcl.rs"]
pub mod pair;

#[macro_use]
extern crate lazy_static;

pub mod signatures;
