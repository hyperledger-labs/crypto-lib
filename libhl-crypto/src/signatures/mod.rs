#[macro_use]
mod macros;
pub mod secp256k1;
pub mod ed25519;

#[cfg(feature = "native")]
use libsecp256k1;

use amcl_3::hash256::HASH256;
use amcl_3::hash512::HASH512;

#[derive(Debug)]
pub enum CryptoError {
    /// Returned when trying to create an algorithm which does not exist.
    NoSuchAlgorithm(String),
    /// Returned when an error occurs during deserialization of a Private or
    /// Public key from various formats.
    ParseError(String),
    /// Returned when an error occurs during the signing process.
    SigningError(String),
    /// Returned when an error occurs during key generation
    KeyGenError(String),
}

#[cfg(feature = "native")]
impl From<libsecp256k1::Error> for CryptoError {
    fn from(error: libsecp256k1::Error) -> CryptoError {
        match error {
            libsecp256k1::Error::IncorrectSignature => CryptoError::ParseError("Incorrect Signature".to_string()),
            libsecp256k1::Error::InvalidMessage => CryptoError::ParseError("Invalid Message".to_string()),
            libsecp256k1::Error::InvalidPublicKey => CryptoError::ParseError("Invalid Public Key".to_string()),
            libsecp256k1::Error::InvalidSignature => CryptoError::ParseError("Invalid Signature".to_string()),
            libsecp256k1::Error::InvalidSecretKey => CryptoError::ParseError("Invalid Secret Key".to_string()),
            libsecp256k1::Error::InvalidRecoveryId => CryptoError::ParseError("Invalid Recovery Id".to_string())
        }
    }
}

pub enum KeyPairOption<'a> {
    UseSeed(Vec<u8>),
    FromSecretKey(&'a PrivateKey)
}

pub trait SignatureScheme {
    fn new() -> Self;
    fn keypair(&self, options: Option<KeyPairOption>) -> Result<(PublicKey, PrivateKey), CryptoError>;
    fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, CryptoError>;
    fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, CryptoError>;
    fn signature_size() -> usize;
    fn private_key_size() -> usize;
    fn public_key_size() -> usize;
}

/// A private key instance.
/// The underlying content is dependent on implementation.
pub struct PrivateKey(Vec<u8>);
impl_bytearray!(PrivateKey);

pub struct PublicKey(Vec<u8>);
impl_bytearray!(PublicKey);

pub struct Signer<'a, 'b, T: 'a + SignatureScheme> {
    scheme: &'a T,
    key: &'b PrivateKey
}

impl<'a, 'b, T: 'a + SignatureScheme> Signer<'a, 'b, T> {
    /// Constructs a new Signer
    ///
    /// # Arguments
    ///
    /// * `scheme` - a cryptographic signature scheme
    /// * `private_key` - private key
    pub fn new(scheme: &'a T, key: &'b PrivateKey) -> Self {
        Signer { scheme, key }
    }

    /// Signs the given message.
    ///
    /// # Arguments
    ///
    /// * `message` - the message bytes
    ///
    /// # Returns
    ///
    /// * `signature` - the signature bytes
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.scheme.sign(message, self.key)
    }

    /// Return the public key for this Signer instance.
    ///
    /// # Returns
    ///
    /// * `public_key` - the public key instance
    pub fn get_public_key(&self) -> Result<PublicKey, CryptoError> {
        let (pubk, _) = self.scheme.keypair(Some(KeyPairOption::FromSecretKey(self.key))).unwrap();
        Ok(pubk)
    }
}

pub trait EcdsaPublicKeyHandler {
    /// Returns the compressed bytes
    fn serialize(&self, pk: &PublicKey) -> Vec<u8>;
    /// Returns the uncompressed bytes
    fn serialize_uncompressed(&self, pk: &PublicKey) -> Vec<u8>;
    /// Read raw bytes into key struct. Can be either compressed or uncompressed
    fn parse(&self, data: &[u8]) -> Result<PublicKey, CryptoError>;
    fn public_key_uncompressed_size() -> usize;
}
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h=HASH256::new();
    h.process_array(data);
    h.hash()
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h=HASH512::new();
    h.process_array(data);
    h.hash()
}

pub fn bin2hex(b: &[u8]) -> String {
    b.iter()
     .map(|b| format!("{:02x}", b))
     .collect::<Vec<_>>()
     .join("")
}

pub fn hex2bin(s: &str) -> Result<Vec<u8>, CryptoError> {
    if s.len() % 2 != 0 {
        return Err(CryptoError::ParseError("Invalid string".to_string()))
    }
    for (i, ch) in s.chars().enumerate() {
        if !ch.is_digit(16) {
            return Err(CryptoError::ParseError(format!("Invalid character position {}", i)));
        }
    }

    let input: Vec<_> = s.chars().collect();

    let decoded: Vec<u8> = input.chunks(2).map(|chunk| {
        ((chunk[0].to_digit(16).unwrap() << 4) |
        (chunk[1].to_digit(16).unwrap())) as u8
    }).collect();

    return Ok(decoded);
}

fn get_u32(n: &[u8]) -> u32 {
    let mut res = 0u32;
    for i in 0..4 {
        res <<= 8;
        res |= n[i] as u32;
    }
    res
}
