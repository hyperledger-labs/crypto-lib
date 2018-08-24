use super::*;

use std::fmt;

use amcl_3::secp256k1::ecdh;

use rand::os::OsRng;

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 33;
pub const PUBLIC_UNCOMPRESSED_KEY_SIZE: usize = 65;
pub const SIGNATURE_POINT_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const ALGORITHM_NAME: &str = "ECDSA_SECP256K1_SHA256";

pub fn new_keys() -> Result<(EcdsaSecp256K1Sha256PrivateKey, EcdsaSecp256K1Sha256PublicKey), CryptoError> {
    let s = EcdsaSecp256K1Sha256PrivateKey::new()?;
    let p = s.get_public_key();
    Ok((s, p))
}

pub struct EcdsaSecp256K1Sha256PublicKey(ecdsa_secp256k1_sha256::EcdsaSecp256K1Sha256PublicKeyImpl);

impl EcdsaSecp256K1Sha256PublicKey {
    pub fn as_slice(&self) -> [u8; PUBLIC_KEY_SIZE] { self.0.as_slice() }
    pub fn as_hex(&self) -> String { self.0.as_hex() }
    pub fn as_uncompressed_slice(&self) -> [u8; PUBLIC_UNCOMPRESSED_KEY_SIZE] { self.0.as_uncompressed_slice() }
    pub fn as_uncompressed_hex(&self) -> String { self.0.as_uncompressed_hex() }
    pub fn from_slice(data: &[u8]) -> Result<EcdsaSecp256K1Sha256PublicKey, CryptoError> {
        let value = ecdsa_secp256k1_sha256::EcdsaSecp256K1Sha256PublicKeyImpl::from_slice(data)?;
        Ok(EcdsaSecp256K1Sha256PublicKey(value))
    }
    pub fn from_hex(data: &str) -> Result<EcdsaSecp256K1Sha256PublicKey, CryptoError> {
        let value = ecdsa_secp256k1_sha256::EcdsaSecp256K1Sha256PublicKeyImpl::from_hex(data)?;
        Ok(EcdsaSecp256K1Sha256PublicKey(value))
    }
}

impl Clone for EcdsaSecp256K1Sha256PublicKey {
    fn clone(&self) -> EcdsaSecp256K1Sha256PublicKey {
        EcdsaSecp256K1Sha256PublicKey(self.0.clone())
    }
}

impl fmt::Display for EcdsaSecp256K1Sha256PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "EcdsaSecp256K1Sha256PublicKey {{ {} }}", self.0)
    }
}

impl fmt::Debug for EcdsaSecp256K1Sha256PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "EcdsaSecp256K1Sha256PublicKey {{ {} }}", self.0)
    }
}

impl Eq for EcdsaSecp256K1Sha256PublicKey {}

impl PartialEq for EcdsaSecp256K1Sha256PublicKey {
    fn eq(&self, other: &EcdsaSecp256K1Sha256PublicKey) -> bool {
        self.0 == other.0
    }
}

impl PublicKey for EcdsaSecp256K1Sha256PublicKey {
    fn get_algorithm_name(&self) -> &str { ALGORITHM_NAME }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        self.0.verify(message, signature)
    }
}

pub struct EcdsaSecp256K1Sha256PrivateKey(ecdsa_secp256k1_sha256::EcdsaSecp256K1Sha256PrivateKeyImpl);

impl EcdsaSecp256K1Sha256PrivateKey {
    pub fn new() -> Result<EcdsaSecp256K1Sha256PrivateKey, CryptoError> {
        let value = ecdsa_secp256k1_sha256::EcdsaSecp256K1Sha256PrivateKeyImpl::new()?;
        Ok(EcdsaSecp256K1Sha256PrivateKey(value))
    }

    pub fn as_slice(&self) -> [u8; PRIVATE_KEY_SIZE] { self.0.as_slice() }

    pub fn as_hex(&self) -> String { self.0.as_hex() }

    pub fn from_slice(data: &[u8]) -> Result<EcdsaSecp256K1Sha256PrivateKey, CryptoError> {
        let value = ecdsa_secp256k1_sha256::EcdsaSecp256K1Sha256PrivateKeyImpl::from_slice(data)?;
        Ok(EcdsaSecp256K1Sha256PrivateKey(value))
    }

    pub fn from_hex(data: &str) -> Result<EcdsaSecp256K1Sha256PrivateKey, CryptoError> {
        let value = ecdsa_secp256k1_sha256::EcdsaSecp256K1Sha256PrivateKeyImpl::from_hex(data)?;
        Ok(EcdsaSecp256K1Sha256PrivateKey(value))
    }
}

impl Clone for EcdsaSecp256K1Sha256PrivateKey {
    fn clone(&self) -> EcdsaSecp256K1Sha256PrivateKey {
        EcdsaSecp256K1Sha256PrivateKey(self.0.clone())
    }
}

impl fmt::Display for EcdsaSecp256K1Sha256PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "EcdsaSecp256K1Sha256PrivateKey {{ {} }}", self.0)
    }
}

impl fmt::Debug for EcdsaSecp256K1Sha256PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "EcdsaSecp256K1Sha256PrivateKey {{ {} }}", self.0)
    }
}

impl Eq for EcdsaSecp256K1Sha256PrivateKey {}

impl PartialEq for EcdsaSecp256K1Sha256PrivateKey {
    fn eq(&self, other: &EcdsaSecp256K1Sha256PrivateKey) -> bool {
        self.0 == other.0
    }
}

impl PrivateKey<EcdsaSecp256K1Sha256PublicKey> for EcdsaSecp256K1Sha256PrivateKey {
    fn get_algorithm_name(&self) -> &str { ALGORITHM_NAME }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0.sign(message)
    }

    fn get_public_key(&self) -> EcdsaSecp256K1Sha256PublicKey {
        let value = self.0.get_public_key();
        EcdsaSecp256K1Sha256PublicKey(value)
    }
}

#[cfg(all(feature = "native", not(feature = "portable")))]
mod ecdsa_secp256k1_sha256 {
    use super::*;
    use libsecp256k1;

    pub struct EcdsaSecp256K1Sha256PublicKeyImpl {
        context: libsecp256k1::Secp256k1<libsecp256k1::VerifyOnly>,
        pk: libsecp256k1::key::PublicKey
    }

    impl EcdsaSecp256K1Sha256PublicKeyImpl {
        pub fn as_slice(&self) -> [u8; PUBLIC_KEY_SIZE] {
            self.pk.serialize()
        }
        pub fn as_hex(&self) -> String {
            bin2hex(&self.as_slice()[..])
        }
        pub fn as_uncompressed_slice(&self) -> [u8; PUBLIC_UNCOMPRESSED_KEY_SIZE] {
            self.pk.serialize_uncompressed()
        }
        pub fn as_uncompressed_hex(&self) -> String {
            bin2hex(&self.as_uncompressed_slice()[..])
        }
        pub fn from_slice(data: &[u8]) -> Result<EcdsaSecp256K1Sha256PublicKeyImpl, CryptoError> {
            if ecdh::public_key_validate(&data[..]) == 0 {
                let context = libsecp256k1::Secp256k1::verification_only();
                let pk = libsecp256k1::key::PublicKey::from_slice(&context, &data)?;
                Ok(EcdsaSecp256K1Sha256PublicKeyImpl { context, pk })
            } else {
                Err(CryptoError::ParseError("Invalid public key".to_string()))
            }
        }
        pub fn from_hex(data: &str) -> Result<EcdsaSecp256K1Sha256PublicKeyImpl, CryptoError> {
            let bytes = hex2bin(data)?;
            EcdsaSecp256K1Sha256PublicKeyImpl::from_slice(bytes.as_slice())
        }
        pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
            let hash = sha256(message);
            let msg = libsecp256k1::Message::from_slice(&hash[..])?;
            let sig = libsecp256k1::Signature::from_compact(&self.context, signature)?;
            let res = self.context.verify(&msg, &sig, &self.pk);
            match res {
                Ok(()) => Ok(true),
                Err(libsecp256k1::Error::IncorrectSignature) => Ok(false),
                Err(err) => Err(CryptoError::from(err))
            }
        }
    }

    impl Clone for EcdsaSecp256K1Sha256PublicKeyImpl {
        fn clone(&self) -> EcdsaSecp256K1Sha256PublicKeyImpl {
            EcdsaSecp256K1Sha256PublicKeyImpl {
                context: libsecp256k1::Secp256k1::verification_only(),
                pk: self.pk.clone()
            }
        }
    }

    impl fmt::Display for EcdsaSecp256K1Sha256PublicKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "EcdsaSecp256K1Sha256PublicKeyImpl {{ context: VerifyOnly, pk: {} }}", bin2hex(&self.pk.serialize()))
        }
    }

    impl fmt::Debug for EcdsaSecp256K1Sha256PublicKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "EcdsaSecp256K1Sha256PublicKeyImpl {{ context: VerifyOnly, pk: {} }}", bin2hex(&self.pk.serialize()))
        }
    }

    impl Eq for EcdsaSecp256K1Sha256PublicKeyImpl {}

    impl PartialEq for EcdsaSecp256K1Sha256PublicKeyImpl {
        fn eq(&self, other: &EcdsaSecp256K1Sha256PublicKeyImpl) -> bool {
            self.pk == other.pk
        }
    }

    pub struct EcdsaSecp256K1Sha256PrivateKeyImpl {
        context: libsecp256k1::Secp256k1<libsecp256k1::SignOnly>,
        sk: libsecp256k1::key::SecretKey
    }

    impl EcdsaSecp256K1Sha256PrivateKeyImpl {
        pub fn new() -> Result<EcdsaSecp256K1Sha256PrivateKeyImpl, CryptoError> {
            let context = libsecp256k1::Secp256k1::signing_only();
            let mut rng = OsRng::new().map_err(|err| CryptoError::KeyGenError(format!("{}", err)))?;
            let sk = libsecp256k1::key::SecretKey::new(&context, &mut rng);
            Ok(EcdsaSecp256K1Sha256PrivateKeyImpl { context, sk })
        }
        pub fn as_slice(&self) -> [u8; PRIVATE_KEY_SIZE] {
            let mut res = [0u8; PRIVATE_KEY_SIZE];
            array_copy!(self.sk[..], res);
            res
        }
        pub fn as_hex(&self) -> String { bin2hex(&self.as_slice()[..]) }
        pub fn from_slice(data: &[u8]) -> Result<EcdsaSecp256K1Sha256PrivateKeyImpl, CryptoError> {
            let context = libsecp256k1::Secp256k1::signing_only();
            let sk = libsecp256k1::SecretKey::from_slice(&context, data)?;
            Ok(EcdsaSecp256K1Sha256PrivateKeyImpl { context, sk })
        }
        pub fn from_hex(data: &str) -> Result<EcdsaSecp256K1Sha256PrivateKeyImpl, CryptoError> {
            let bytes = hex2bin(data)?;
            EcdsaSecp256K1Sha256PrivateKeyImpl::from_slice(bytes.as_slice())
        }
        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let hash = sha256(message);
            let msg = libsecp256k1::Message::from_slice(&hash[..])?;
            let sig = self.context.sign(&msg, &self.sk);
            Ok(sig.serialize_compact(&self.context).to_vec())
        }
        pub fn get_public_key(&self) -> EcdsaSecp256K1Sha256PublicKeyImpl {
            let pk = libsecp256k1::key::PublicKey::from_secret_key(&self.context, &self.sk);
            let context = libsecp256k1::Secp256k1::verification_only();
            EcdsaSecp256K1Sha256PublicKeyImpl { context, pk }
        }
    }

    impl Clone for EcdsaSecp256K1Sha256PrivateKeyImpl {
        fn clone(&self) -> EcdsaSecp256K1Sha256PrivateKeyImpl {
            EcdsaSecp256K1Sha256PrivateKeyImpl {
                context: libsecp256k1::Secp256k1::signing_only(),
                sk: self.sk.clone()
            }
        }
    }

    impl fmt::Display for EcdsaSecp256K1Sha256PrivateKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "EcdsaSecp256K1Sha256PrivateKeyImpl {{ context: SignOnly, sk: {} }}", bin2hex(&self.sk[..]))
        }
    }

    impl fmt::Debug for EcdsaSecp256K1Sha256PrivateKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "EcdsaSecp256K1Sha256PrivateKeyImpl {{ context: SignOnly, sk: {} }}", bin2hex(&self.sk[..]))
        }
    }

    impl Eq for EcdsaSecp256K1Sha256PrivateKeyImpl {}

    impl PartialEq for EcdsaSecp256K1Sha256PrivateKeyImpl {
        fn eq(&self, other: &EcdsaSecp256K1Sha256PrivateKeyImpl) -> bool {
            self.sk == other.sk
        }
    }
}

#[cfg(all(feature = "portable", not(feature = "native")))]
mod ecdsa_secp256k1_sha256 {
    use super::*;

    use rand::Rng;

//    use amcl_3::rand::RAND;
    use amcl_3::secp256k1::ecp;

    use rustlibsecp256k1;

//    const HALF_CURVE_ORDER: [u32; 8] = [0x681B20A0, 0xDFE92F46, 0x57A4501D, 0x5D576E73, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF];
//    const CURVE_C: [u32; 5] = [!HALF_CURVE_ORDER[0] + 1, !HALF_CURVE_ORDER[1], !HALF_CURVE_ORDER[2], !HALF_CURVE_ORDER[3], 1u32];
//    const CURVE_ORDER: [u32; 8] = [0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];

    pub struct EcdsaSecp256K1Sha256PublicKeyImpl([u8; PUBLIC_KEY_SIZE]);

    impl EcdsaSecp256K1Sha256PublicKeyImpl {
        pub fn as_slice(&self) -> [u8; PUBLIC_KEY_SIZE] { self.0 }
        pub fn as_hex(&self) -> String {
            bin2hex(&self.as_slice()[..])
        }
        pub fn as_uncompressed_slice(&self) -> [u8; PUBLIC_UNCOMPRESSED_KEY_SIZE] {
            let mut uncompressed = [0u8; PUBLIC_UNCOMPRESSED_KEY_SIZE];
            ecp::ECP::frombytes(&self.0[..]).tobytes(&mut uncompressed, false);
            uncompressed
        }
        pub fn as_uncompressed_hex(&self) -> String {
            bin2hex(&self.as_uncompressed_slice()[..])
        }
        pub fn from_slice(data: &[u8]) -> Result<EcdsaSecp256K1Sha256PublicKeyImpl, CryptoError> {
            if ecdh::public_key_validate(data) == 0 {
                let mut value = [0u8; PUBLIC_KEY_SIZE];
                match data.len() {
                    PUBLIC_KEY_SIZE => array_copy!(data, value),
                    PUBLIC_UNCOMPRESSED_KEY_SIZE => ecp::ECP::frombytes(data).tobytes(&mut value, true),
                    _ => Err(CryptoError::ParseError("Invalid public key".to_string()))?
                };
//                ecp::ECP::frombytes(data).tobytes(&mut value, true);
                Ok(EcdsaSecp256K1Sha256PublicKeyImpl(value))
            } else {
                Err(CryptoError::ParseError("Invalid public key".to_string()))
            }
        }
        pub fn from_hex(data: &str) -> Result<EcdsaSecp256K1Sha256PublicKeyImpl, CryptoError> {
            let bytes = hex2bin(data)?;
            EcdsaSecp256K1Sha256PublicKeyImpl::from_slice(bytes.as_slice())
        }
        pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
            if signature.len() != SIGNATURE_SIZE {
                Err(CryptoError::ParseError("Invalid signature length".to_string()))?
            }
//            let r = array_ref!(signature, 0, SIGNATURE_POINT_SIZE);
//            let s = array_ref!(signature, SIGNATURE_POINT_SIZE, SIGNATURE_POINT_SIZE);
//            let result = ecdh::ecpvp_dsa(ecdh::SHA256, &self.0[..], &message, &r[..], &s[..]);
//
//            Ok(result == 0)
            let hash = sha256(message);
            match rustlibsecp256k1::verify(&hash, array_ref!(signature, 0, 64), &self.as_uncompressed_slice()) {
                Ok(b) => Ok(b),
                Err(_) => Err(CryptoError::SigningError("Incorrect signature".to_string()))
            }
        }
    }

    impl Clone for EcdsaSecp256K1Sha256PublicKeyImpl {
        fn clone(&self) -> EcdsaSecp256K1Sha256PublicKeyImpl {
            let mut value = [0u8; PUBLIC_KEY_SIZE];
            array_copy!(&self.0[..], value);
            EcdsaSecp256K1Sha256PublicKeyImpl(value)
        }
    }

    impl fmt::Display for EcdsaSecp256K1Sha256PublicKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "EcdsaSecp256K1Sha256PublicKeyImpl {{ {} }}", bin2hex(&self.0[..]))
        }
    }

    impl fmt::Debug for EcdsaSecp256K1Sha256PublicKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "EcdsaSecp256K1Sha256PublicKeyImpl {{ {} }}", bin2hex(&self.0[..]))
        }
    }

    impl Eq for EcdsaSecp256K1Sha256PublicKeyImpl {}

    impl PartialEq for EcdsaSecp256K1Sha256PublicKeyImpl {
        fn eq(&self, other: &EcdsaSecp256K1Sha256PublicKeyImpl) -> bool {
            array_compare(&self.0[..], &other.0[..])
        }
    }

    pub struct EcdsaSecp256K1Sha256PrivateKeyImpl([u8; PRIVATE_KEY_SIZE]);

    impl EcdsaSecp256K1Sha256PrivateKeyImpl {
        pub fn new() -> Result<EcdsaSecp256K1Sha256PrivateKeyImpl, CryptoError> {
            let mut rng = OsRng::new().map_err(|err| CryptoError::KeyGenError(format!("{}", err)))?;
            let mut value = [0u8; PRIVATE_KEY_SIZE];
            rng.fill_bytes(&mut value);
            Ok(EcdsaSecp256K1Sha256PrivateKeyImpl(value))
        }
        pub fn as_slice(&self) -> [u8; PRIVATE_KEY_SIZE] { self.0 }
        pub fn as_hex(&self) -> String { bin2hex(&self.as_slice()[..]) }
        pub fn from_slice(data: &[u8]) -> Result<EcdsaSecp256K1Sha256PrivateKeyImpl, CryptoError> {
            if data.len() == PRIVATE_KEY_SIZE {
                let mut value = [0u8; PRIVATE_KEY_SIZE];
                array_copy!(data, value);
                Ok(EcdsaSecp256K1Sha256PrivateKeyImpl(value))
            } else {
                Err(CryptoError::KeyGenError(format!("Expected {} bytes for a private key", PRIVATE_KEY_SIZE)))
            }
        }
        pub fn from_hex(data: &str) -> Result<EcdsaSecp256K1Sha256PrivateKeyImpl, CryptoError> {
            let bytes = hex2bin(data)?;
            EcdsaSecp256K1Sha256PrivateKeyImpl::from_slice(bytes.as_slice())
        }
        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
//            let mut r = [0u8; SIGNATURE_POINT_SIZE];
//            let mut s = [0u8; SIGNATURE_POINT_SIZE];
//            let mut pool = RAND::new();
//            let mut seed = [0u8; 128];
//            get_random_seed(&mut seed)?;
//            pool.seed(seed.len(), &seed);
//            ecdh::ecpsp_dsa(ecdh::SHA256, &mut pool, &self.0[..], &message, &mut r, &mut s);
//
//            Use the "low s" form to be compatible with libsecp256k1
//            normalize_s(&mut s);
//            let mut signature = Vec::new();
//            signature.extend_from_slice(&r[..]);
//            signature.extend_from_slice(&s[..]);

//            Ok(signature)
            let hash = sha256(message);
            match rustlibsecp256k1::sign(&hash, &self.0) {
                Ok(sig) => Ok(sig.to_vec()),
                Err(_) => Err(CryptoError::SigningError("".to_string()))
            }
        }
        pub fn get_public_key(&self) -> EcdsaSecp256K1Sha256PublicKeyImpl {
            let mut w = [0u8; PUBLIC_KEY_SIZE]; //Compressed
            let mut s = [0u8; PRIVATE_KEY_SIZE];
            array_copy!(&self.0[..], s);
            ecdh::key_pair_generate(None, &mut s, &mut w);
            zero!(s);
            EcdsaSecp256K1Sha256PublicKeyImpl(w)
        }
    }

    impl Clone for EcdsaSecp256K1Sha256PrivateKeyImpl {
        fn clone(&self) -> EcdsaSecp256K1Sha256PrivateKeyImpl {
            let mut value = [0u8; PRIVATE_KEY_SIZE];
            array_copy!(self.0, value);
            EcdsaSecp256K1Sha256PrivateKeyImpl(value)
        }
    }

    impl fmt::Display for EcdsaSecp256K1Sha256PrivateKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "EcdsaSecp256K1Sha256PrivateKeyImpl {{ {} }}", bin2hex(&self.0[..]))
        }
    }

    impl fmt::Debug for EcdsaSecp256K1Sha256PrivateKeyImpl {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "EcdsaSecp256K1Sha256PrivateKeyImpl {{ {} }}", bin2hex(&self.0[..]))
        }
    }

    impl Eq for EcdsaSecp256K1Sha256PrivateKeyImpl {}

    impl PartialEq for EcdsaSecp256K1Sha256PrivateKeyImpl {
        fn eq(&self, other: &EcdsaSecp256K1Sha256PrivateKeyImpl) -> bool {
            array_compare(&self.0[..], &other.0[..])
        }
    }

//    fn normalize_s(s: &mut [u8; 32]) {
//        let mut new_s = set_b32(s);
//        if is_high(&new_s) {
//            negate(&mut new_s);
//            let s_tmp = get_b32(&new_s);
//            array_copy!(s_tmp, s);
//        }
//    }
//
//    /// Convert a little-endian byte array to 8 32 bit numbers
//    fn set_b32(s: &[u8; 32]) -> [u32; 8] {
//        let mut new_s = [0u32; 8];
//
//        fn get_u32(n: &[u8]) -> u32 {
//            let mut res = 0u32;
//            for i in 0..4 {
//                res <<= 8;
//                res |= n[i] as u32;
//            }
//            res
//        }
//
//        new_s[0] = get_u32(&s[28..32]);
//        new_s[1] = get_u32(&s[24..28]);
//        new_s[2] = get_u32(&s[20..24]);
//        new_s[3] = get_u32(&s[16..20]);
//        new_s[4] = get_u32(&s[12..16]);
//        new_s[5] = get_u32(&s[8..12]);
//        new_s[6] = get_u32(&s[4..8]);
//        new_s[7] = get_u32(&s[0..4]);
//
//        let overflow = check_overflow(&new_s);
//        reduce(&mut new_s, overflow);
//        new_s
//    }
//
//    /// Convert 8 32 bit numbers array to a little-endian byte array.
//    fn get_b32(s: &[u32; 8]) -> [u8; 32] {
//        let mut new_s = [0u8; 32];
//        let mut index = 0;
//        for i in 0..8 {
//            let mut shift = 24;
//            for _ in 0..4 {
//                new_s[index] = (s[7 - i] >> shift) as u8;
//                index += 1;
//                shift -= 8;
//            }
//        }
//        new_s
//    }
//
//    /// Check whether a scalar is higher than the group order divided
///// by 2.
//    fn is_high(s: &[u32; 8]) -> bool {
//        let mut yes: bool = false;
//        let mut no: bool = false;
//        no = no || (s[7] < HALF_CURVE_ORDER[7]);
//        yes = yes || ((s[7] > HALF_CURVE_ORDER[7]) & !no);
//        no = no || ((s[6] < HALF_CURVE_ORDER[6]) & !yes); /* No need for a > check. */
//        no = no || ((s[5] < HALF_CURVE_ORDER[5]) & !yes); /* No need for a > check. */
//        no = no || ((s[4] < HALF_CURVE_ORDER[4]) & !yes); /* No need for a > check. */
//        no = no || ((s[3] < HALF_CURVE_ORDER[3]) & !yes);
//        yes = yes || ((s[3] > HALF_CURVE_ORDER[3]) && !no);
//        no = no || ((s[2] < HALF_CURVE_ORDER[2]) && !yes);
//        yes = yes || ((s[2] > HALF_CURVE_ORDER[2]) && !no);
//        no = no || ((s[1] < HALF_CURVE_ORDER[1]) && !yes);
//        yes = yes || ((s[1] > HALF_CURVE_ORDER[1]) && !no);
//        yes = yes || ((s[0] >= HALF_CURVE_ORDER[0]) && !no);
//        yes
//    }
//
//    fn negate(s: &mut [u32; 8]) {
//        let nonzero = if is_zero(s) { 0u64 } else { 0xFFFFFFFFu64 };
//        let mut t = (!s[0]) as u64 + (CURVE_ORDER[0] + 1) as u64;
//
//        for i in 0..7 {
//            s[i] = (t & nonzero) as u32;
//            t >>= 32;
//            t += (!s[i + 1]) as u64 + CURVE_ORDER[i + 1] as u64;
//        }
//        s[7] = (t & nonzero) as u32;
//    }
//
//    fn is_zero(s: &[u32; 8]) -> bool {
//        s.iter().all(|b| *b == 0)
//    }
//
//    fn check_overflow(s: &[u32; 8]) -> bool {
//        let mut yes: bool = false;
//        let mut no: bool = false;
//        for i in 0..3 {
//            no = no || (s[7 - i] < CURVE_ORDER[7 - i])
//        }
//        for i in 0..4 {
//            no = no || (s[4 - i] < CURVE_ORDER[4 - i]);
//            yes = yes || ((s[4 - i] > CURVE_ORDER[4 - i]) && !no);
//        }
//        yes = yes || ((s[0] >= CURVE_ORDER[0]) && !no);
//        yes
//    }
//
//    fn reduce(s: &mut [u32; 8], overflow: bool) {
//        let o = if overflow { 1u64 } else { 0u64 };
//        let mut t = 0u64;
//
//        for i in 0..5 {
//            t += (s[i] as u64) + o * (CURVE_C[i] as u64);
//            s[i] = (t & 0xFFFFFFFF) as u32;
//            t >>= 32;
//        }
//
//        for i in 5..7 {
//            t += s[i] as u64;
//            s[i] = (t & 0xFFFFFFFF) as u32;
//            t >>= 32;
//        }
//
//        t += s[7] as u64;
//        s[7] = (t & 0xFFFFFFFF) as u32;
//    }
//
//    #[cfg(not(test))]
//    fn get_random_seed(seed: &mut [u8]) -> Result<(), CryptoError> {
//        let mut rng = OsRng::new().map_err(|err| CryptoError::KeyGenError(format!("{}", err)))?;
//        rng.fill_bytes(seed);
//        Ok(())
//    }
//
//    #[cfg(test)]
//    fn get_random_seed(seed: &mut [u8]) -> Result<(), CryptoError> {
//    for i in 0..seed.len() {
//        seed[i] = i as u8;
//    }
//    Ok(())
//}
}

#[cfg(test)]
mod test {
    use super::*;
    use libsecp256k1;
    use openssl::ecdsa::EcdsaSig;
    use openssl::ec::{EcGroup, EcPoint, EcKey};
    use openssl::nid::Nid;
    use openssl::bn::{BigNum, BigNumContext};

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "ae46d3fec8e2eb95ebeaf95f7f096ec4bf517f5ef898e4379651f8af8e209ed75f3c47156445d6687a5f817fb3e188e2a76df653b330df859ec47579c8c409be";
    const PRIVATE_KEY: &str = "e4f21b38e005d4f895a29e84948d7cc83eac79041aeb644ee4fab8d9da42f713";
    const PUBLIC_KEY: &str = "0242c1e1f775237a26da4fd51b8d75ee2709711f6e90303e511169a324ef0789c0";

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
    fn secp256k1_load_keys() {
        assert!(EcdsaSecp256K1Sha256PrivateKey::from_hex(PRIVATE_KEY).is_ok());
        assert!(EcdsaSecp256K1Sha256PrivateKey::from_hex("1293857b11d").is_err());
        assert!(EcdsaSecp256K1Sha256PublicKey::from_hex(PUBLIC_KEY).is_ok());
        assert!(EcdsaSecp256K1Sha256PublicKey::from_hex("1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/0987654321").is_err());
    }

    #[test]
    fn secp256k1_compatibility() {
        let s = EcdsaSecp256K1Sha256PrivateKey::from_hex(PRIVATE_KEY).unwrap();
        let p = EcdsaSecp256K1Sha256PublicKey::from_hex(PUBLIC_KEY).unwrap();

        let p_u = EcdsaSecp256K1Sha256PublicKey::from_slice(&p.as_uncompressed_slice());
        assert!(p_u.is_ok());
        let p_u = p_u.unwrap();
        assert_eq!(p_u, p);

        let context = libsecp256k1::Secp256k1::new();
        let sk = libsecp256k1::key::SecretKey::from_slice(&context, &s.as_slice());
        assert!(sk.is_ok());
        let pk = libsecp256k1::key::PublicKey::from_slice(&context, &p.as_slice()[..]);
        assert!(pk.is_ok());
        let pk = libsecp256k1::key::PublicKey::from_slice(&context, &p.as_uncompressed_slice()[..]);
        assert!(pk.is_ok());

        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let openssl_point = EcPoint::from_bytes(&openssl_group, &p.as_uncompressed_slice()[..], &mut ctx);
        assert!(openssl_point.is_ok());
    }

    #[test]
    fn secp256k1_verify() {
        let p = EcdsaSecp256K1Sha256PublicKey::from_hex(PUBLIC_KEY).unwrap();
        let result = p.verify(&MESSAGE_1, hex2bin(SIGNATURE_1).unwrap().as_slice());
        assert!(result.is_ok());
        assert!(result.unwrap());

        let context = libsecp256k1::Secp256k1::new();
        let pk = libsecp256k1::key::PublicKey::from_slice(&context, hex2bin(PUBLIC_KEY).unwrap().as_slice()).unwrap();

        let hash= sha256(&MESSAGE_1);
        let msg = libsecp256k1::Message::from_slice(&hash[..]).unwrap();

        //Check if signatures produced here can be verified by libsecp256k1
        let mut signature = libsecp256k1::Signature::from_compact(&context, &hex2bin(SIGNATURE_1).unwrap()[..]).unwrap();
        signature.normalize_s(&context);
        let result = context.verify(&msg, &signature, &pk);
        assert!(result.is_ok());

        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let openssl_point = EcPoint::from_bytes(&openssl_group, &pk.serialize_uncompressed(), &mut ctx).unwrap();
        let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();

        //Check if the signatures produced here can be verified by openssl
        let (r, s) = SIGNATURE_1.split_at(SIGNATURE_1.len() / 2);
        let openssl_r = BigNum::from_hex_str(r).unwrap();
        let openssl_s = BigNum::from_hex_str(s).unwrap();
        let openssl_sig = EcdsaSig::from_private_components(openssl_r, openssl_s).unwrap();
        let openssl_result = openssl_sig.verify(&hash, &openssl_pkey);
        assert!(openssl_result.is_ok());
        assert!(openssl_result.unwrap());
    }

    #[test]
    fn secp256k1_sign() {
        let s = EcdsaSecp256K1Sha256PrivateKey::from_hex(PRIVATE_KEY).unwrap();
        let p = EcdsaSecp256K1Sha256PublicKey::from_hex(PUBLIC_KEY).unwrap();

        match s.sign(MESSAGE_1) {
            Ok(sig) => {
                let result = p.verify(&MESSAGE_1, &sig);
                assert!(result.is_ok());
                assert!(result.unwrap());

                assert_eq!(sig.len(), SIGNATURE_SIZE);

                //This will only match if the PRNG is seeded. We can seed it for amcl, but not libsecp256k1
//                if cfg!(feature = "portable") {
//                    assert_eq!(bin2hex(sig.as_slice()), SIGNATURE_1);
//                }

                //Check if libsecp256k1 signs the message and this module still can verify it
                //And that private keys can sign with other libraries
                let mut context = libsecp256k1::Secp256k1::new();
                let sk = libsecp256k1::key::SecretKey::from_slice(&context, hex2bin(PRIVATE_KEY).unwrap().as_slice()).unwrap();

                let hash= sha256(&MESSAGE_1);

                let msg = libsecp256k1::Message::from_slice(&hash[..]).unwrap();
                let sig_1 = context.sign(&msg, &sk).serialize_compact(&context);

                let result = p.verify(&MESSAGE_1, &sig_1);

                assert!(result.is_ok());
                assert!(result.unwrap());

                let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
                let mut ctx = BigNumContext::new().unwrap();
                let openssl_point = EcPoint::from_bytes(&openssl_group, &p.as_uncompressed_slice()[..], &mut ctx).unwrap();
                let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();
                let openssl_skey = EcKey::from_private_components(&openssl_group, &BigNum::from_hex_str(PRIVATE_KEY).unwrap(), &openssl_point).unwrap();

                let openssl_sig = EcdsaSig::sign(&hash, &openssl_skey).unwrap();
                let openssl_result = openssl_sig.verify(&hash, &openssl_pkey);
                assert!(openssl_result.is_ok());
                assert!(openssl_result.unwrap());
                let mut temp_sig = Vec::new();
                temp_sig.extend(openssl_sig.r().to_vec());
                temp_sig.extend(openssl_sig.s().to_vec());
                let result = p.verify(&MESSAGE_1, temp_sig.as_slice());
                assert!(result.is_ok());
                assert!(result.unwrap());

                let (s, p) = new_keys().unwrap();
                match s.sign(&MESSAGE_1) {
                    Ok(signed) => {
                        let result = p.verify(&MESSAGE_1, &signed);
                        assert!(result.is_ok());
                        assert!(result.unwrap());
                    },
                    Err(er) => assert!(false, er)
                }
            },
            Err(e) => assert!(false, e)
        }
    }


}
