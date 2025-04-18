use k256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier},
};

pub struct K256Signer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl K256Signer {
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = VerifyingKey::from(&signing_key);
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(message);
        signature.to_vec()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), String> {
        let sig = Signature::try_from(signature).map_err(|e| e.to_string())?;
        self.verifying_key
            .verify(message, &sig)
            .map_err(|e| e.to_string())
    }
}
