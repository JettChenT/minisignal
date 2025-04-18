use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct X25519KeyExchange {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl X25519KeyExchange {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random();
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn get_public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn compute_shared_secret(self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer_public = PublicKey::from(*peer_public);
        let shared_secret = self.secret.diffie_hellman(&peer_public);
        shared_secret.to_bytes()
    }
}
