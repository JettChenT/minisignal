use kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

pub fn mlkem_demo() {
    let mut rng = rand::thread_rng();
    let (dk, ek) = <MlKem768 as KemCore>::generate(&mut rng);
    let (ct, _ss) = ek.encapsulate(&mut rng).unwrap();
    dk.decapsulate(&ct).unwrap();
    println!("ML-KEM key exchange completed");
}
