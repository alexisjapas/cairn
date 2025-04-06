use k256::{
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    elliptic_curve::rand_core::OsRng,
};
use sha2::{Digest, Sha256};

fn main() {
    // Generate pair of keys
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);

    // Message
    let message = "Hello, world!";

    // Sign the message hash
    let mut original_hasher = Sha256::new();
    original_hasher.update(message.as_bytes());
    let original_hash = original_hasher.finalize();
    let signature: Signature = signing_key.sign(original_hash.as_slice());

    // Verify the signature
    let mut verifier_hasher = Sha256::new();
    verifier_hasher.update(message.as_bytes());
    let verifier_hash = verifier_hasher.finalize();
    let result = verifying_key.verify(verifier_hash.as_slice(), &signature);
    if result.is_ok() {
        println!("Signature OK for:\n{}", message);
    } else {
        println!("Signature verification failed");
    }
}
