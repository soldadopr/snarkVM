use snarkvm_utilities::{bits_from_bytes_le, bytes_from_bits_le};
use tiny_keccak::{Hasher, Keccak, Sha3};

/// Defines a common interface for different hash algorithms.
trait CryptoHash {
    fn hash_bytes(&self, input: &[u8]) -> Vec<u8>;
}

struct Keccak224;
struct Keccak256;
struct Keccak384;
struct Keccak512;
struct Sha3224;
struct Sha3256;
struct Sha3384;
struct Sha3512;

impl CryptoHash for Keccak224 {
    fn hash_bytes(&self, input: &[u8]) -> Vec<u8> {
        let mut keccak = Keccak::v224();
        keccak.update(input);
        let mut output = [0u8; 28];
        keccak.finalize(&mut output);
        output.to_vec()
    }
}

impl CryptoHash for Keccak256 {
    fn hash_bytes(&self, input: &[u8]) -> Vec<u8> {
        let mut keccak = Keccak::v256();
        keccak.update(input);
        let mut output = [0u8; 32];
        keccak.finalize(&mut output);
        output.to_vec()
    }
}

impl CryptoHash for Keccak384 {
    fn hash_bytes(&self, input: &[u8]) -> Vec<u8> {
        let mut keccak = Keccak::v384();
        keccak.update(input);
        let mut output = [0u8; 48];
        keccak.finalize(&mut output);
        output.to_vec()
    }
}

impl CryptoHash for Keccak512 {
    fn hash_bytes(&self, input: &[u8]) -> Vec<u8> {
        let mut keccak = Keccak::v512();
        keccak.update(input);
        let mut output = [0u8; 64];
        keccak.finalize(&mut output);
        output.to_vec()
    }
}

impl CryptoHash for Sha3224 {
    fn hash_bytes(&self, input: &[u8]) -> Vec<u8> {
        let mut sha3 = Sha3::v224();
        sha3.update(input);
        let mut output = [0u8; 28];
        sha3.finalize(&mut output);
        output.to_vec()
    }
}

// Implement `CryptoHash` for other SHA3 variants similarly...

// Example usage in a testing context:
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_224() {
        let hasher = Keccak224;
        let input = b"hello world";
        let hash = hasher.hash_bytes(input);
        println!("Keccak-224 hash of 'hello world': {:?}", hash);
        // Add your assertions here...
    }

    // More tests for other hash types...
}
