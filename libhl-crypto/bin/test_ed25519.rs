extern crate hl_crypto;
extern crate libsodium_ffi as ffi;

use hl_crypto::signatures::ed25519::Ed25519PrivateKey;
use hl_crypto::signatures::{PublicKey, PrivateKey};

use std::io;
use std::io::Write;
use std::time::Instant;

fn main() {
    let letters = b"abcdefghijklmnopqrstuvwxyz";
    let trials = 200;
    println!("Running 3 tests for ed25519 signing of {} messages", trials);
    print!("This library - ");
    io::stdout().flush().unwrap();
    let s = Ed25519PrivateKey::new().unwrap();
    let p = s.get_public_key();
    let mut now = Instant::now();

    for _ in 0..trials {
        let signature = s.sign(&letters[..]).unwrap();
        p.verify(&letters[..], &signature).unwrap();
    }
    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    let mut signature = [0u8; 64];
    print!("libsodium based ed25519 - ");
    io::stdout().flush().unwrap();

    now = Instant::now();
    for _ in 0..trials {
        unsafe {
            ffi::crypto_sign_ed25519_detached(signature.as_mut_ptr() as *mut u8,
                                              0u64 as *mut u64,
                                              letters.as_ptr() as *const u8,
                                              letters.len() as u64,
                                              s.as_slice().as_ptr() as *const u8);

            ffi::crypto_sign_ed25519_verify_detached(signature.as_ptr() as *const u8,
                                                     letters.as_ptr() as *const u8,
                                                     letters.len() as u64,
                                                     p.as_slice().as_ptr() as *const u8)
        };
    }

    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());
}
