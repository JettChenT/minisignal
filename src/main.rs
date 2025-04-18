use rand::{RngCore, thread_rng};
use std::io::{self, Write};

mod aesgcm;
mod dalek;
mod mlkem;
mod xcurve;

fn main() {
    println!("MiniSignal Cryptographic Operations Demo");
    println!("---------------------------------------");

    // AES-GCM Demo
    println!("\n1. AES-GCM Encryption/Decryption:");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    thread_rng().fill_bytes(&mut key);
    thread_rng().fill_bytes(&mut nonce);

    let cipher = aesgcm::AesGcmCipher::new(&key);
    let message = b"Hello, Encryption!";
    let encrypted = cipher.encrypt(message, &nonce).unwrap();
    let decrypted = cipher.decrypt(&encrypted, &nonce).unwrap();
    println!("Original: {:?}", String::from_utf8_lossy(message));
    println!("Encrypted (hex): {:?}", hex::encode(&encrypted));
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));

    // X25519 Demo
    println!("\n2. X25519 Key Exchange:");
    let alice = dalek::X25519KeyExchange::new();
    let bob = dalek::X25519KeyExchange::new();

    let alice_pk = alice.get_public_key();
    let bob_pk = bob.get_public_key();
    let alice_shared = alice.compute_shared_secret(&bob_pk);
    let bob_shared = bob.compute_shared_secret(&alice_pk);
    println!("Alice's shared secret: {}", hex::encode(&alice_shared));
    println!("Bob's shared secret: {}", hex::encode(&bob_shared));
    println!("Shared secrets match: {}", alice_shared == bob_shared);

    // ML-KEM Demo
    println!("\n3. ML-KEM Post-Quantum Key Exchange:");
    mlkem::mlkem_demo();

    // K-256 Signing Demo
    println!("\n4. K-256 Digital Signature:");
    let signer = xcurve::K256Signer::new();
    let message = b"Sign this message";
    let signature = signer.sign(message);
    let verification = signer.verify(message, &signature);
    println!("Message: {:?}", String::from_utf8_lossy(message));
    println!("Signature (hex): {}", hex::encode(&signature));
    println!("Verification result: {:?}", verification);
}
