use super::*;

use std::fmt;

use rand::Rng;
use rand::os::OsRng;

use amcl_3::rand::RAND;
use amcl_3::secp256k1::ecdh;

pub const PRIVATE_KEY_SIZE: usize = ecdh::EFS;
pub const PUBLIC_KEY_SIZE: usize = ecdh::EFS+1;
pub const SIGNATURE_POINT_SIZE: usize = ecdh::EFS;
pub const SIGNATURE_SIZE: usize = ecdh::EFS*2;
pub const ALGORITHM_NAME: &str = "ECDSA_SECP256K1_SHA256";

const HALF_CURVE_ORDER: [u32; 8] = [0x681B20A0, 0xDFE92F46, 0x57A4501D, 0x5D576E73, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF];
const CURVE_C: [u32; 5] = [!HALF_CURVE_ORDER[0] + 1, !HALF_CURVE_ORDER[1], !HALF_CURVE_ORDER[2], !HALF_CURVE_ORDER[3], 1u32];
const CURVE_ORDER: [u32; 8] = [0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];

pub fn new_keys() -> Result<(EcdsaSecp256K1Sha256PrivateKey, EcdsaSecp256K1Sha256PublicKey), CryptoError> {
    let s = EcdsaSecp256K1Sha256PrivateKey::new()?;
    let p = s.get_public_key()?;
    Ok((s, p))
}

pub struct EcdsaSecp256K1Sha256PublicKey {
    value: [u8; PUBLIC_KEY_SIZE]
}

impl EcdsaSecp256K1Sha256PublicKey {
    pub fn as_slice(&self) -> &[u8] {
        &self.value[..]
    }

    pub fn as_hex(&self) -> String {
        bin2hex(&self.value[..])
    }

    pub fn from_slice(data: &[u8]) -> Result<EcdsaSecp256K1Sha256PublicKey, CryptoError> {
        if data.len() != PUBLIC_KEY_SIZE {
            Err(CryptoError::KeyGenError(format!("Expected {} bytes for a public key", PUBLIC_KEY_SIZE)))
        } else {
            let mut value = [0u8; PUBLIC_KEY_SIZE];
            array_copy!(data, value);
            Ok(EcdsaSecp256K1Sha256PublicKey { value })
        }
    }

    pub fn from_hex(data: &str) -> Result<EcdsaSecp256K1Sha256PublicKey, CryptoError> {
        let bin = hex2bin(data)?;
        EcdsaSecp256K1Sha256PublicKey::from_slice(bin.as_slice())
    }
}

impl Clone for EcdsaSecp256K1Sha256PublicKey {
    fn clone(&self) -> EcdsaSecp256K1Sha256PublicKey {
        EcdsaSecp256K1Sha256PublicKey::from_slice(&self.value[..]).unwrap()
    }
}

impl fmt::Display for EcdsaSecp256K1Sha256PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "EcdsaSecp256K1Sha256PublicKey {{ value: {} }}", bin2hex(&self.value))
    }
}

impl fmt::Debug for EcdsaSecp256K1Sha256PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "EcdsaSecp256K1Sha256PublicKey {{ value: {} }}", bin2hex(&self.value))
    }
}

impl Eq for EcdsaSecp256K1Sha256PublicKey {}

impl PartialEq for EcdsaSecp256K1Sha256PublicKey {
    fn eq(&self, other: &EcdsaSecp256K1Sha256PublicKey) -> bool {
        safe_array_compare(&self.value, &other.value)
    }
}

impl PublicKey for EcdsaSecp256K1Sha256PublicKey {
    fn get_algorithm_name(&self) -> &str {
        ALGORITHM_NAME
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        if signature.len() != SIGNATURE_SIZE {
            Err(CryptoError::ParseError("Invalid signature length".to_string()))?
        }
        let r = array_ref!(signature, 0, SIGNATURE_POINT_SIZE);
        let s = array_ref!(signature, SIGNATURE_POINT_SIZE, SIGNATURE_POINT_SIZE);
        let result = ecdh::ecpvp_dsa(ecdh::SHA256, &self.value, &message, &r[..], &s[..]);

        Ok(result == 0)
    }
}

pub struct EcdsaSecp256K1Sha256PrivateKey {
    value: [u8; PRIVATE_KEY_SIZE]
}

impl EcdsaSecp256K1Sha256PrivateKey {
    pub fn new() -> Result<EcdsaSecp256K1Sha256PrivateKey, CryptoError> {
        let mut rng = OsRng::new().map_err(|err| CryptoError::KeyGenError(format!("{}", err)))?;
        let mut value = [0u8; PRIVATE_KEY_SIZE];
        rng.fill_bytes(&mut value);
        Ok(EcdsaSecp256K1Sha256PrivateKey { value })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.value[..]
    }

    pub fn as_hex(&self) -> String {
        bin2hex(&self.value[..])
    }

    pub fn from_slice(data: &[u8]) -> Result<EcdsaSecp256K1Sha256PrivateKey, CryptoError> {
        if data.len() != PRIVATE_KEY_SIZE {
            Err(CryptoError::KeyGenError(format!("Expected {} bytes for a private key", PRIVATE_KEY_SIZE)))
        } else {
            let mut value = [0u8; PRIVATE_KEY_SIZE];
            array_copy!(data, value);
            Ok(EcdsaSecp256K1Sha256PrivateKey { value })
        }
    }

    pub fn from_hex(data: &str) -> Result<EcdsaSecp256K1Sha256PrivateKey, CryptoError> {
        let bin = hex2bin(data)?;
        EcdsaSecp256K1Sha256PrivateKey::from_slice(bin.as_slice())
    }
}

impl Clone for EcdsaSecp256K1Sha256PrivateKey {
    fn clone(&self) -> EcdsaSecp256K1Sha256PrivateKey {
        EcdsaSecp256K1Sha256PrivateKey::from_slice(&self.value[..]).unwrap()
    }
}

impl fmt::Display for EcdsaSecp256K1Sha256PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "EcdsaSecp256K1Sha256PrivateKey {{ value: {} }}", self.as_hex())
    }
}

impl fmt::Debug for EcdsaSecp256K1Sha256PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "EcdsaSecp256K1Sha256PrivateKey {{ value: {} }}", self.as_hex())
    }
}

impl Eq for EcdsaSecp256K1Sha256PrivateKey {}

impl PartialEq for EcdsaSecp256K1Sha256PrivateKey {
    fn eq(&self, other: &EcdsaSecp256K1Sha256PrivateKey) -> bool {
        safe_array_compare(&self.value, &other.value)
    }
}

impl PrivateKey<EcdsaSecp256K1Sha256PublicKey> for EcdsaSecp256K1Sha256PrivateKey {
    fn get_algorithm_name(&self) -> &str {
        ALGORITHM_NAME
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut r = [0u8; SIGNATURE_POINT_SIZE];
        let mut s = [0u8; SIGNATURE_POINT_SIZE];
        let mut pool = RAND::new();
        let mut seed = [0u8; 128];
        get_random_seed(&mut seed)?;
        pool.seed(seed.len(), &seed);
        ecdh::ecpsp_dsa(ecdh::SHA256, &mut pool, &self.value, &message, &mut r, &mut s);

        //Use the "low s" form to be compatible with libsecp256k1
        normalize_s(&mut s);
        let mut signature = Vec::new();
        signature.extend_from_slice(&r[..]);
        signature.extend_from_slice(&s[..]);

        Ok(signature)
    }

    fn get_public_key(&self) -> Result<EcdsaSecp256K1Sha256PublicKey, CryptoError> {
        let mut w = [0u8; PUBLIC_KEY_SIZE]; //Compressed
        let mut s = [0u8; PRIVATE_KEY_SIZE];
        array_copy!(self.value, s);
        ecdh::key_pair_generate(None, &mut s, &mut w);
        zero!(s);
        if ecdh::public_key_validate(&w) == 0 {
            Ok(EcdsaSecp256K1Sha256PublicKey { value: w })
        } else {
            Err(CryptoError::KeyGenError("Invalid private key".to_string()))
        }
    }
}

fn normalize_s(s: &mut [u8; 32]) {
    let mut new_s = set_b32(s);
    if is_high(&new_s) {
        negate(&mut new_s);
        let s_tmp = get_b32(&new_s);
        array_copy!(s_tmp, s);
    }
}

fn set_b32(s: &[u8; 32]) -> [u32; 8] {
    let mut new_s = [0u32; 8];

    fn get_u32(n: &[u8]) -> u32 {
        let mut res = 0u32;
        for i in 0..4 {
            res <<= 8;
            res |= n[i] as u32;
        }
        res
    }

    new_s[0] = get_u32(&s[28..32]);
    new_s[1] = get_u32(&s[24..28]);
    new_s[2] = get_u32(&s[20..24]);
    new_s[3] = get_u32(&s[16..20]);
    new_s[4] = get_u32(&s[12..16]);
    new_s[5] = get_u32(&s[8..12]);
    new_s[6] = get_u32(&s[4..8]);
    new_s[7] = get_u32(&s[0..4]);

    let overflow = check_overflow(&new_s);
    reduce(&mut new_s, overflow);
    new_s
}

/// Convert a scalar to a byte array.
pub fn get_b32(s: &[u32; 8]) -> [u8; 32] {
    let mut new_s = [0u8; 32];
    let mut index = 0;
    for i in 0..8 {
        let mut shift = 24;
        for _ in 0..4 {
            new_s[index] = (s[7 - i] >> shift) as u8;
            index += 1;
            shift -= 8;
        }
    }
    new_s
}

/// Check whether a scalar is higher than the group order divided
/// by 2.
fn is_high(s: &[u32; 8]) -> bool {
    let mut yes: bool = false;
    let mut no: bool = false;
    no = no || (s[7] < HALF_CURVE_ORDER[7]);
    yes = yes || ((s[7] > HALF_CURVE_ORDER[7]) & !no);
    no = no || ((s[6] < HALF_CURVE_ORDER[6]) & !yes); /* No need for a > check. */
    no = no || ((s[5] < HALF_CURVE_ORDER[5]) & !yes); /* No need for a > check. */
    no = no || ((s[4] < HALF_CURVE_ORDER[4]) & !yes); /* No need for a > check. */
    no = no || ((s[3] < HALF_CURVE_ORDER[3]) & !yes);
    yes = yes || ((s[3] > HALF_CURVE_ORDER[3]) && !no);
    no = no || ((s[2] < HALF_CURVE_ORDER[2]) && !yes);
    yes = yes || ((s[2] > HALF_CURVE_ORDER[2]) && !no);
    no = no || ((s[1] < HALF_CURVE_ORDER[1]) && !yes);
    yes = yes || ((s[1] > HALF_CURVE_ORDER[1]) && !no);
    yes = yes || ((s[0] >= HALF_CURVE_ORDER[0]) && !no);
    yes
}

pub fn negate(s: &mut [u32; 8]) {
    let nonzero = if is_zero(s) { 0u64 } else { 0xFFFFFFFFu64 };
    let mut t = (!s[0]) as u64 + (CURVE_ORDER[0] + 1) as u64;

    for i in 0..7 {
        s[i] = (t & nonzero) as u32;
        t >>= 32;
        t += (!s[i + 1]) as u64 + CURVE_ORDER[i + 1] as u64;
    }
    s[7] = (t & nonzero) as u32;
}

fn is_zero(s: &[u32; 8]) -> bool {
    s.iter().all(|b| *b == 0)
}

fn check_overflow(s: &[u32; 8]) -> bool {
    let mut yes: bool = false;
    let mut no: bool = false;
    for i in 0..3 {
        no = no || (s[7 - i] < CURVE_ORDER[7 - i])
    }
    for i in 0..4 {
        no = no || (s[4 - i] < CURVE_ORDER[4 - i]);
        yes = yes || ((s[4 - i] > CURVE_ORDER[4 - i]) && !no);
    }
    yes = yes || ((s[0] >= CURVE_ORDER[0]) && !no);
    yes
}

fn reduce(s: &mut [u32; 8], overflow: bool) {
    let o = if overflow { 1u64 } else { 0u64 };
    let mut t = 0u64;

    for i in 0..5 {
        t += (s[i] as u64) + o * (CURVE_C[i] as u64);
        s[i] = (t & 0xFFFFFFFF) as u32;
        t >>= 32;
    }

    for i in 5..7 {
        t += s[i] as u64;
        s[i] = (t & 0xFFFFFFFF) as u32;
        t >>= 32;
    }

    t += s[7] as u64;
    s[7] = (t & 0xFFFFFFFF) as u32;
}

#[cfg(not(test))]
fn get_random_seed(seed: &mut [u8]) -> Result<(), CryptoError> {
    let mut rng = OsRng::new().map_err(|err| CryptoError::KeyGenError(format!("{}", err)))?;
    rng.fill_bytes(seed);
    Ok(())
}

#[cfg(test)]
fn get_random_seed(seed: &mut [u8]) -> Result<(), CryptoError> {
    for i in 0..seed.len() {
        seed[i] = i as u8;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use secp256k1;
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
    fn secp256k1_verify() {
        let p = EcdsaSecp256K1Sha256PublicKey::from_hex(PUBLIC_KEY).unwrap();
        let result = p.verify(&MESSAGE_1, hex2bin(SIGNATURE_1).unwrap().as_slice());
        assert!(result.is_ok());
        assert!(result.unwrap());

        let context = secp256k1::Secp256k1::new();
        let pk = secp256k1::key::PublicKey::from_slice(&context, hex2bin(PUBLIC_KEY).unwrap().as_slice()).unwrap();

        let mut hash= [0u8;32];
        ecdh::hashit(ecdh::SHA256, &MESSAGE_1, 0, None, 32, &mut hash);
        let msg = secp256k1::Message::from_slice(&hash[..]).unwrap();

        //Check if signatures produced here can be verified by libsecp256k1
        let mut signature = secp256k1::Signature::from_compact(&context, &hex2bin(SIGNATURE_1).unwrap()[..]).unwrap();
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
                assert_eq!(bin2hex(sig.as_slice()), SIGNATURE_1);

                //Check if libsecp256k1 signs the message and this module still can verify it
                //And that private keys can sign with other libraries
                let mut context = secp256k1::Secp256k1::new();
                let sk = secp256k1::key::SecretKey::from_slice(&context, hex2bin(PRIVATE_KEY).unwrap().as_slice()).unwrap();

                let mut hash= [0u8;32];
                ecdh::hashit(ecdh::SHA256, &MESSAGE_1, 0, None, 32, &mut hash);

                let msg = secp256k1::Message::from_slice(&hash[..]).unwrap();
                let sig_1 = context.sign(&msg, &sk).serialize_compact(&context);

                let result = p.verify(&MESSAGE_1, &sig_1);

                assert!(result.is_ok());
                assert!(result.unwrap());

                let pk = secp256k1::key::PublicKey::from_slice(&context, hex2bin(PUBLIC_KEY).unwrap().as_slice()).unwrap();
                let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
                let mut ctx = BigNumContext::new().unwrap();
                let openssl_point = EcPoint::from_bytes(&openssl_group, &pk.serialize_uncompressed(), &mut ctx).unwrap();
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
            },
            Err(e) => panic!(e)
        }
    }
}
