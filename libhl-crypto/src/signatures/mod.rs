#[macro_use]
mod macros;
pub mod secp256k1;
//pub mod ed25519;

#[cfg(feature = "native")]
use libsecp256k1;

use amcl_3::hash256::HASH256;

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

/// A private key instance.
/// The underlying content is dependent on implementation.
pub trait PrivateKey<T: Sized + PublicKey> {
    /// Returns the algorithm name used for this private key.
    fn get_algorithm_name(&self) -> &str;
    /// Sign a message
    /// and return a byte array of the resulting signature.
    /// # Arguments
    /// * `message`- the message bytes to sign
    /// # Returns
    /// * `signature` - The signature in a binary array
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Produce the public key for the given private key.
    /// # Returns
    /// * `public_key` - the public key for the given private key
    fn get_public_key(&self) -> T;
}

/// A public key instance.
/// The underlying content is dependent on implementation.
pub trait PublicKey {
    /// Returns the algorithm name used for this public key.
    fn get_algorithm_name(&self) -> &str;
    /// Verify a message with a signature
    /// # Arguments
    /// * `message` - the message bytes that were signed
    /// * `signature` - the signature returned from *sign*
    /// # Returns
    /// * `boolean` - True if `message` this public key is associated with the signature,
    ///               False otherwise
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h=HASH256::new();
    h.process_array(data);
    h.hash()
}

fn array_compare(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() &&
    a.iter().enumerate().all(|(i, v)| *v == b[i])
}

fn bin2hex(b: &[u8]) -> String {
    b.iter()
     .map(|b| format!("{:02x}", b))
     .collect::<Vec<_>>()
     .join("")
}

fn hex2bin(s: &str) -> Result<Vec<u8>, CryptoError> {
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
