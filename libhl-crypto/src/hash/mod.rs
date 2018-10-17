use CryptoError;

#[derive(Debug)]
pub enum DigestAlgorithm {
    SHA2_256,
    SHA2_384,
    SHA2_512
}

pub fn digest(algorithm: DigestAlgorithm, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        DigestAlgorithm::SHA2_256 => {
            let mut hash = sha2::SHA256Hash::new();
            hash.update(message);
            hash.finalize()
        },
        DigestAlgorithm::SHA2_384 => {
            let mut hash = sha2::SHA384Hash::new();
            hash.update(message);
            hash.finalize()
        },
        DigestAlgorithm::SHA2_512 => {
            let mut hash = sha2::SHA512Hash::new();
            hash.update(message);
            hash.finalize()
        }
    }
}

pub trait Digest {
    fn new() -> Self where Self : Sized;
    fn reset(&mut self);
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Result<Vec<u8>, CryptoError>;
}

pub mod sha2;
