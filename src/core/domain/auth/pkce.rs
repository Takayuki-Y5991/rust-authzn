use base64ct::{Base64UrlUnpadded, Encoding};
use rand::{rngs::OsRng, TryRngCore};
use sha2::{Digest, Sha256};

use super::error::AuthError;

#[derive(Debug, Clone)]
pub struct CodeVerifier(String);
impl CodeVerifier {
  pub fn generate() -> Self {
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];

    let _ = rng
      .try_fill_bytes(&mut bytes)
      .map_err(|e| AuthError::ValidationError(format!("Failed to generate random bytes: {}", e)));

    let value = encode_to_string(&bytes);
    Self(value)
  }

  pub fn value(&self) -> &str {
    &self.0
  }
}

#[derive(Debug, Clone)]
pub struct CodeChallenge(String);

impl CodeChallenge {
  pub fn from_verifier(verifier: &CodeVerifier) -> Self {
    let mut hasher = Sha256::new();
    hasher.update(verifier.value().as_bytes());
    let result = hasher.finalize();
    let challenge = encode_to_string(&result);
    Self(challenge)
  }
  pub fn value(&self) -> &str {
    &self.0
  }
}

fn encode_to_string(bytes: &[u8]) -> String {
  let mut buffer = vec![0; Base64UrlUnpadded::encoded_len(bytes)];
  Base64UrlUnpadded::encode(bytes, &mut buffer).unwrap();
  return String::from_utf8(buffer).unwrap();
}
