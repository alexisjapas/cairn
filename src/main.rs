use k256::{
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    elliptic_curve::rand_core::OsRng,
};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Alice keys
    let alice_signing_key = SigningKey::random(&mut OsRng);
    let alice_verifying_key = VerifyingKey::from(&alice_signing_key);

    // Bob keys
    let bob_signing_key = SigningKey::random(&mut OsRng);
    let bob_verifying_key = VerifyingKey::from(&bob_signing_key);

    // New transaction from alice to bob
    let mut transaction = Transaction::new(alice_verifying_key, bob_verifying_key, 1);

    // Sign the transaction
    transaction.sign(&alice_signing_key);

    // Verify the transaction
    match transaction.verify() {
        true => println!("Transaction is legit!"),
        false => println!("Transaction has been falsified!"),
    }

    /////////////////////
    // Falsified examples
    println!("Falsified transactions:");

    // Wrong key
    let mut transaction = Transaction::new(alice_verifying_key, bob_verifying_key, 1);
    // Sign the transaction with another key
    transaction.sign(&bob_signing_key);
    // Verify the transaction
    match transaction.verify() {
        true => println!("Transaction is legit!"),
        false => println!("Transaction has been falsified!"),
    }

    // Changed value
    let mut transaction = Transaction::new(alice_verifying_key, bob_verifying_key, 1);
    // Sign the transaction
    transaction.sign(&alice_signing_key);
    // Change the amount
    transaction.amount = 100;
    // Verify the transaction
    match transaction.verify() {
        true => println!("Transaction is legit!"),
        false => println!("Transaction has been falsified!"),
    }
}

struct Transaction {
    sender: VerifyingKey,
    receiver: VerifyingKey,
    amount: u64,
    timestamp: u128,
    signature: Option<Signature>,
}

impl Transaction {
    fn new(sender: VerifyingKey, receiver: VerifyingKey, amount: u64) -> Transaction {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards!")
            .as_millis();
        Transaction {
            sender,
            receiver,
            amount,
            timestamp,
            signature: None,
        }
    }

    fn verify(&self) -> bool {
        match &self.signature {
            Some(signature) => {
                let hash = self._hash();
                self.sender.verify(&hash, signature).is_ok()
            }
            None => false,
        }
    }

    fn sign(&mut self, signing_key: &SigningKey) {
        // Verify if the signing_key is owned by sender
        if VerifyingKey::from(signing_key) == self.sender {
            let hash = self._hash();
            self.signature = Some(signing_key.sign(&hash));
        }
    }

    fn _hash(&self) -> [u8; 32] {
        let transaction_bytes = self._to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&transaction_bytes);
        hasher.finalize().into()
    }

    fn _to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.sender.to_sec1_bytes());
        bytes.extend_from_slice(&self.receiver.to_sec1_bytes());
        bytes.extend_from_slice(&self.amount.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes
    }
}
