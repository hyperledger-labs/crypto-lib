extern crate amcl_3;
extern crate rand;
extern crate hl_crypto;
extern crate secp256k1;
extern crate openssl;

use hl_crypto::signatures::secp256k1::EcdsaSecp256K1Sha256PrivateKey;
use hl_crypto::signatures::{PublicKey, PrivateKey};
use openssl::ecdsa::EcdsaSig;
use openssl::ec::{EcGroup, EcPoint, EcKey};
use openssl::nid::Nid;
use openssl::bn::{BigNum, BigNumContext};
use amcl_3::hash256::HASH256;

use std::io;
use std::io::Write;
use std::time::Instant;

fn main() {
    let letters = b"abcdefghijklmnopqrstuvwxyz";
    let trials = 200;
    println!("Running 3 tests for secp256k1 signing of {} messages", trials);
    print!("This library - ");
    io::stdout().flush().unwrap();
    let s = EcdsaSecp256K1Sha256PrivateKey::new().unwrap();
    let p = s.get_public_key().unwrap();
    let mut now = Instant::now();

    for _ in 0..trials {
        let signature = s.sign(&letters[..]).unwrap();
        p.verify(&letters[..], &signature).unwrap();
    }
    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    print!("C based secp256k1 - ");
    io::stdout().flush().unwrap();
    let context = secp256k1::Secp256k1::new();
    let sk = secp256k1::key::SecretKey::from_slice(&context, s.as_slice()).unwrap();
    let pk = secp256k1::key::PublicKey::from_slice(&context, p.as_slice()).unwrap();

    now = Instant::now();
    for _ in 0..trials {
        let hash = sha256(&letters[..]);
        let msg = secp256k1::Message::from_slice(&hash[..]).unwrap();
        let sig_1 = context.sign(&msg, &sk);
        context.verify(&msg, &sig_1, &pk).unwrap();
    }

    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());

    print!("Openssl based secp256k1 - ");
    io::stdout().flush().unwrap();
    let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let openssl_point = EcPoint::from_bytes(&openssl_group, &p.as_uncompressed_slice()[..], &mut ctx).unwrap();
    let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();
    let openssl_skey = EcKey::from_private_components(&openssl_group, &BigNum::from_slice(s.as_slice()).unwrap(), &openssl_point).unwrap();

    now = Instant::now();
    for _ in 0..trials {
        let hash = sha256(&letters[..]);
        let openssl_sig = EcdsaSig::sign(&hash, &openssl_skey).unwrap();
        openssl_sig.verify(&hash, &openssl_pkey).unwrap();
    }

    let elapsed = now.elapsed();
    println!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis());
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h=HASH256::new();
    h.process_array(data);
    h.hash()
}
