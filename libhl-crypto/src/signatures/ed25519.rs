use super::*;

use std::fmt;

pub const ALGORITHM_NAME: &str = "ED25519_SHA2-512";
pub const PRIVATE_KEY_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const SIGNATURE_POINT_SIZE: usize = 32;

pub fn new_keys() -> Result<(Ed25519PrivateKey, Ed25519PublicKey), CryptoError> {
    let (sk, pk) = ed25519_sha2_512::new_keys()?;
    Ok((Ed25519PrivateKey(sk), Ed25519PublicKey(pk)))
}

pub struct Ed25519PublicKey(ed25519_sha2_512::Ed25519PublicKeyImpl);

impl Ed25519PublicKey {
    pub fn as_slice(&self) -> [u8; PUBLIC_KEY_SIZE] { self.0.as_slice() }
    pub fn as_hex(&self) -> String { self.0.as_hex() }
    pub fn from_slice(data: &[u8]) -> Result<Ed25519PublicKey, CryptoError> {
        let value = ed25519_sha2_512::Ed25519PublicKeyImpl::from_slice(data)?;
        Ok(Ed25519PublicKey(value))
    }
    pub fn from_hex(data: &str) -> Result<Ed25519PublicKey, CryptoError> {
        let value = ed25519_sha2_512::Ed25519PublicKeyImpl::from_hex(data)?;
        Ok(Ed25519PublicKey(value))
    }
}

impl Clone for Ed25519PublicKey {
    fn clone(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.0.clone())
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Ed25519PublicKey {{ {} }}", self.0)
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Ed25519PublicKey {{ {} }}", self.0)
    }
}

impl Eq for Ed25519PublicKey {}

impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Ed25519PublicKey) -> bool {
        self.0 == other.0
    }
}

impl PublicKey for Ed25519PublicKey {
    fn get_algorithm_name(&self) -> &str { ALGORITHM_NAME }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        self.0.verify(message, signature)
    }
}

pub struct Ed25519PrivateKey(ed25519_sha2_512::Ed25519PrivateKeyImpl);

impl Ed25519PrivateKey {
    pub fn new() -> Result<Ed25519PrivateKey, CryptoError> {
        let value = ed25519_sha2_512::Ed25519PrivateKeyImpl::new()?;
        Ok(Ed25519PrivateKey(value))
    }

    pub fn as_slice(&self) -> [u8; PRIVATE_KEY_SIZE] { self.0.as_slice() }

    pub fn as_hex(&self) -> String { self.0.as_hex() }

    pub fn from_slice(data: &[u8]) -> Result<Ed25519PrivateKey, CryptoError> {
        let value = ed25519_sha2_512::Ed25519PrivateKeyImpl::from_slice(data)?;
        Ok(Ed25519PrivateKey(value))
    }

    pub fn from_hex(data: &str) -> Result<Ed25519PrivateKey, CryptoError> {
        let value = ed25519_sha2_512::Ed25519PrivateKeyImpl::from_hex(data)?;
        Ok(Ed25519PrivateKey(value))
    }
}

impl Clone for Ed25519PrivateKey {
    fn clone(&self) -> Ed25519PrivateKey {
        Ed25519PrivateKey(self.0.clone())
    }
}

impl fmt::Display for Ed25519PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Ed25519PrivateKey {{ {} }}", self.0)
    }
}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Ed25519PrivateKey {{ {} }}", self.0)
    }
}

impl Eq for Ed25519PrivateKey {}

impl PartialEq for Ed25519PrivateKey {
    fn eq(&self, other: &Ed25519PrivateKey) -> bool {
        self.0 == other.0
    }
}

impl PrivateKey<Ed25519PublicKey> for Ed25519PrivateKey {
    fn get_algorithm_name(&self) -> &str { ALGORITHM_NAME }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0.sign(message)
    }

    fn get_public_key(&self) -> Ed25519PublicKey {
        let value = self.0.get_public_key();
        Ed25519PublicKey(value)
    }
}

#[cfg(all(feature = "native", not(feature = "portable")))]
mod ed25519_sha2_512 {
    use super::*;
    use libsodium_ffi as ffi;

    pub fn new_keys() -> Result<(Ed25519PrivateKeyImpl, Ed25519PublicKeyImpl), CryptoError> {
        let mut sk = [0u8; ffi::crypto_sign_ed25519_SECRETKEYBYTES];
        let mut pk = [0u8; ffi::crypto_sign_ed25519_PUBLICKEYBYTES];
        let res = unsafe {
            ffi::crypto_sign_keypair(pk.as_mut_ptr() as *mut u8, sk.as_mut_ptr() as *mut u8)
        };
        if res == 0 {
            Ok((Ed25519PrivateKeyImpl(sk),
                Ed25519PublicKeyImpl(pk)))
        } else {
            Err(CryptoError::KeyGenError("Unable to generate new keys".to_string()))
        }
    }

    pub struct Ed25519PublicKeyImpl([u8; ffi::crypto_sign_ed25519_PUBLICKEYBYTES]);

    impl Ed25519PublicKeyImpl {
        pub fn as_slice(&self) -> [u8; ffi::crypto_sign_ed25519_PUBLICKEYBYTES] { self.0 }
        pub fn as_hex(&self) -> String { bin2hex(&self.as_slice()[..]) }
        pub fn from_slice(data: &[u8]) -> Result<Ed25519PublicKeyImpl, CryptoError> {
            if data.len() == ffi::crypto_sign_ed25519_PUBLICKEYBYTES {
                let mut value = [0u8; ffi::crypto_sign_ed25519_PUBLICKEYBYTES];
                array_copy!(data, value);
                Ok(Ed25519PublicKeyImpl(value))
            } else {
                Err(CryptoError::ParseError("Invalid public key".to_string()))
            }
        }
        pub fn from_hex(data: &str) -> Result<Ed25519PublicKeyImpl, CryptoError> {
            let bytes = hex2bin(data)?;
            Ed25519PublicKeyImpl::from_slice(bytes.as_slice())
        }
        pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
            let res = unsafe {
                ffi::crypto_sign_ed25519_verify_detached(signature.as_ptr() as *const u8,
                                                         message.as_ptr() as *const u8,
                                                         message.len() as u64,
                                                         self.0.as_ptr() as *const u8)
            };
            Ok(res == 0)
        }
    }

    impl Clone for Ed25519PublicKeyImpl {
        fn clone(&self) -> Ed25519PublicKeyImpl {
            Ed25519PublicKeyImpl::from_slice(&self.0[..]).unwrap()
        }
    }

    impl fmt::Display for Ed25519PublicKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "Ed25519PublicKeyImpl {{ {} }}", bin2hex(&self.0))
        }
    }

    impl fmt::Debug for Ed25519PublicKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "Ed25519PublicKeyImpl {{ {} }}", bin2hex(&self.0))
        }
    }

    impl Eq for Ed25519PublicKeyImpl {}

    impl PartialEq for Ed25519PublicKeyImpl {
        fn eq(&self, other: &Ed25519PublicKeyImpl) -> bool {
            array_compare(&self.0, &other.0)
        }
    }

    pub struct Ed25519PrivateKeyImpl([u8; ffi::crypto_sign_ed25519_SECRETKEYBYTES]);

    impl Ed25519PrivateKeyImpl {
        pub fn new() -> Result<Ed25519PrivateKeyImpl, CryptoError> {
            let mut sk = [0u8; ffi::crypto_sign_ed25519_SECRETKEYBYTES];
            let mut pk = [0u8; ffi::crypto_sign_ed25519_PUBLICKEYBYTES];
            let res = unsafe {
                ffi::crypto_sign_keypair(pk.as_mut_ptr() as *mut u8, sk.as_mut_ptr() as *mut u8)
            };
            if res == 0 {
                Ok(Ed25519PrivateKeyImpl(sk))
            } else {
                Err(CryptoError::KeyGenError("Unable to generate new keys".to_string()))
            }
        }
        pub fn as_slice(&self) -> [u8; PRIVATE_KEY_SIZE] { self.0 }
        pub fn as_hex(&self) -> String { bin2hex(&self.0[..]) }
        pub fn from_slice(data: &[u8]) -> Result<Ed25519PrivateKeyImpl, CryptoError> {
            if data.len() == ffi::crypto_sign_ed25519_SECRETKEYBYTES {
                let mut value = [0u8; ffi::crypto_sign_ed25519_SECRETKEYBYTES];
                array_copy!(data, value);
                Ok(Ed25519PrivateKeyImpl(value))
            } else {
                Err(CryptoError::ParseError("Invalid private key".to_string()))
            }
        }
        pub fn from_hex(data: &str) -> Result<Ed25519PrivateKeyImpl, CryptoError> {
            let bytes = hex2bin(data)?;
            Ed25519PrivateKeyImpl::from_slice(bytes.as_slice())
        }
        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let mut signature = [0u8; ffi::crypto_sign_ed25519_BYTES];
            let res = unsafe {
                ffi::crypto_sign_ed25519_detached(signature.as_mut_ptr() as *mut u8,
                                                  0u64 as *mut u64,
                                                  message.as_ptr() as *const u8,
                                                  message.len() as u64,
                                                  self.0.as_ptr() as *const u8)
            };
            if res == 0 {
                let mut sig = Vec::new();
                sig.extend_from_slice(&signature);
                Ok(sig)
            } else {
                Err(CryptoError::SigningError("An error occurred while signing".to_string()))
            }
        }
        pub fn get_public_key(&self) -> Ed25519PublicKeyImpl {
            let mut value = [0u8; PUBLIC_KEY_SIZE];
            array_copy!(self.0[32..], value);
            Ed25519PublicKeyImpl(value)
        }
    }

    impl Clone for Ed25519PrivateKeyImpl {
        fn clone(&self) -> Ed25519PrivateKeyImpl {
            Ed25519PrivateKeyImpl::from_slice(&self.0[..]).unwrap()
        }
    }

    impl fmt::Display for Ed25519PrivateKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "Ed25519PrivateKeyImpl {{ {} }}", self.as_hex())
        }
    }

    impl fmt::Debug for Ed25519PrivateKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "Ed25519PrivateKeyImpl {{ {} }}", self.as_hex())
        }
    }

    impl Eq for Ed25519PrivateKeyImpl {}

    impl PartialEq for Ed25519PrivateKeyImpl {
        fn eq(&self, other: &Ed25519PrivateKeyImpl) -> bool {
            array_compare(&self.0, &other.0)
        }
    }
}

#[cfg(all(feature = "portable", not(feature = "native")))]
mod ed25519_sha2_512 {
    use super::*;

    use rand::Rng;
    use rand::os::OsRng;

    use rcrypto;

    pub fn new_keys() -> Result<(Ed25519PrivateKeyImpl, Ed25519PublicKeyImpl), CryptoError> {
        let s = Ed25519PrivateKeyImpl::new()?;
        let p = Ed25519PublicKeyImpl::from_slice(&s.as_slice()[32..])?;
        Ok((s, p))
    }

    pub struct Ed25519PublicKeyImpl([u8; PUBLIC_KEY_SIZE]);

    impl Ed25519PublicKeyImpl {
        pub fn as_slice(&self) -> [u8; PUBLIC_KEY_SIZE] { self.0 }
        pub fn as_hex(&self) -> String {
            bin2hex(&self.as_slice()[..])
        }
        pub fn from_slice(data: &[u8]) -> Result<Ed25519PublicKeyImpl, CryptoError> {
            if data.len() == PUBLIC_KEY_SIZE {
                let mut temp = [0u8; PUBLIC_KEY_SIZE];
                array_copy!(data, temp);
                Ok(Ed25519PublicKeyImpl(temp))
            } else {
                Err(CryptoError::ParseError("Invalid public key".to_string()))
            }
        }
        pub fn from_hex(data: &str) -> Result<Ed25519PublicKeyImpl, CryptoError> {
            let bytes = hex2bin(data)?;
            Ed25519PublicKeyImpl::from_slice(bytes.as_slice())
        }
        pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
            if signature.len() != SIGNATURE_SIZE {
                Err(CryptoError::ParseError("Invalid signature length".to_string()))?
            }
            Ok(rcrypto::ed25519::verify(message, &self.0[..], signature))
        }
    }

    impl Clone for Ed25519PublicKeyImpl {
        fn clone(&self) -> Ed25519PublicKeyImpl {
            let mut value = [0u8; PUBLIC_KEY_SIZE];
            array_copy!(&self.0[..], value);
            Ed25519PublicKeyImpl(value)
        }
    }

    impl fmt::Display for Ed25519PublicKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "Ed25519PublicKeyImpl {{ {} }}", bin2hex(&self.0[..]))
        }
    }

    impl fmt::Debug for Ed25519PublicKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "Ed25519PublicKeyImpl {{ {} }}", bin2hex(&self.0[..]))
        }
    }

    impl Eq for Ed25519PublicKeyImpl {}

    impl PartialEq for Ed25519PublicKeyImpl {
        fn eq(&self, other: &Ed25519PublicKeyImpl) -> bool {
            array_compare(&self.0[..], &other.0[..])
        }
    }

    pub struct Ed25519PrivateKeyImpl([u8; PRIVATE_KEY_SIZE]);

    impl Ed25519PrivateKeyImpl {
        pub fn new() -> Result<Ed25519PrivateKeyImpl, CryptoError> {
            let mut rng = OsRng::new().map_err(|err| CryptoError::KeyGenError(format!("{}", err)))?;
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let (sk, _) = rcrypto::ed25519::keypair(&seed);

            Ok(Ed25519PrivateKeyImpl(sk))
        }
        pub fn as_slice(&self) -> [u8; PRIVATE_KEY_SIZE] { self.0 }
        pub fn as_hex(&self) -> String { bin2hex(&self.as_slice()[..]) }
        pub fn from_slice(data: &[u8]) -> Result<Ed25519PrivateKeyImpl, CryptoError> {
            if data.len() == PRIVATE_KEY_SIZE {
                let mut value = [0u8; PRIVATE_KEY_SIZE];
                array_copy!(data, value);
                Ok(Ed25519PrivateKeyImpl(value))
            } else {
                Err(CryptoError::KeyGenError(format!("Expected {} bytes for a private key", PRIVATE_KEY_SIZE)))
            }
        }
        pub fn from_hex(data: &str) -> Result<Ed25519PrivateKeyImpl, CryptoError> {
            let bytes = hex2bin(data)?;
            Ed25519PrivateKeyImpl::from_slice(bytes.as_slice())
        }
        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Ok(rcrypto::ed25519::signature(message, &self.0).to_vec())
        }
        pub fn get_public_key(&self) -> Ed25519PublicKeyImpl {
            let mut value = [0u8; PUBLIC_KEY_SIZE];
            array_copy!(self.0[32..], value);
            Ed25519PublicKeyImpl(value)
        }
    }

    impl Clone for Ed25519PrivateKeyImpl {
        fn clone(&self) -> Ed25519PrivateKeyImpl {
            let mut value = [0u8; PRIVATE_KEY_SIZE];
            array_copy!(self.0, value);
            Ed25519PrivateKeyImpl(value)
        }
    }

    impl fmt::Display for Ed25519PrivateKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "Ed25519PrivateKeyImpl {{ {} }}", bin2hex(&self.0[..]))
        }
    }

    impl fmt::Debug for Ed25519PrivateKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "Ed25519PrivateKeyImpl {{ {} }}", bin2hex(&self.0[..]))
        }
    }

    impl Eq for Ed25519PrivateKeyImpl {}

    impl PartialEq for Ed25519PrivateKeyImpl {
        fn eq(&self, other: &Ed25519PrivateKeyImpl) -> bool {
            array_compare(&self.0[..], &other.0[..])
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use libsodium_ffi as ffi;

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5eefb74134138315859a32c7cf5fe5a488bc545e2e08e5eedfd1fb10188d532d808";
    const PRIVATE_KEY: &str = "1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";
    const PUBLIC_KEY: &str = "27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";

    #[test]
    #[ignore]
    fn create_new_keys() {
        let (s, p) = new_keys().unwrap();

        println!("{:?}", s);
        println!("{:?}", p);
        assert_eq!(s.get_algorithm_name(), ALGORITHM_NAME);
        assert_eq!(p.get_algorithm_name(), ALGORITHM_NAME);
    }

    #[test]
    fn ed25519_load_keys() {
        assert!(Ed25519PrivateKey::from_hex(PRIVATE_KEY).is_ok());
        assert!(Ed25519PrivateKey::from_hex("1293857b11d").is_err());
        assert!(Ed25519PublicKey::from_hex(PUBLIC_KEY).is_ok());
        assert!(Ed25519PublicKey::from_hex("1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/0987654321").is_err());
    }

    #[test]
    fn ed25519_verify() {
        let p = Ed25519PublicKey::from_hex(PUBLIC_KEY).unwrap();
        let result = p.verify(&MESSAGE_1, hex2bin(SIGNATURE_1).unwrap().as_slice());
        assert!(result.is_ok());
        assert!(result.unwrap());

        //Check if signatures produced here can be verified by libsodium
        let signature = hex2bin(SIGNATURE_1).unwrap();
        let res = unsafe {
            ffi::crypto_sign_ed25519_verify_detached(signature.as_slice().as_ptr() as *const u8,
                                                     MESSAGE_1.as_ptr() as *const u8,
                                                     MESSAGE_1.len() as u64,
                                                     p.as_slice().as_ptr() as *const u8)
        };
        assert_eq!(res, 0);
    }

    #[test]
    fn ed25519_sign() {
        let s = Ed25519PrivateKey::from_hex(PRIVATE_KEY).unwrap();
        let p = Ed25519PublicKey::from_hex(PUBLIC_KEY).unwrap();

        match s.sign(&MESSAGE_1) {
            Ok(sig) => {
                let result = p.verify(&MESSAGE_1, &sig);
                assert!(result.is_ok());
                assert!(result.unwrap());

                assert_eq!(sig.len(), SIGNATURE_SIZE);
                assert_eq!(bin2hex(sig.as_slice()), SIGNATURE_1);

                //Check if libsodium signs the message and this module still can verify it
                //And that private keys can sign with other libraries
                let mut signature = [0u8; ffi::crypto_sign_ed25519_BYTES];
                unsafe {
                    ffi::crypto_sign_ed25519_detached(signature.as_mut_ptr() as *mut u8,
                                                      0u64 as *mut u64,
                                                      MESSAGE_1.as_ptr() as *const u8,
                                                      MESSAGE_1.len() as u64,
                                                      s.as_slice().as_ptr() as *const u8)
                };
                let result = p.verify(&MESSAGE_1, &signature);
                assert!(result.is_ok());
                assert!(result.unwrap());
            },
            Err(e) => assert!(false, e)
        }
    }
}
