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
    let mut t_0 = Transaction::new(alice_verifying_key, bob_verifying_key, 1);

    // Sign the transaction
    t_0.sign(&alice_signing_key);

    // Verify the transaction
    match t_0.verify() {
        true => println!("Transaction is legit!"),
        false => println!("Transaction has been falsified!"),
    }

    // Other transactions to add to the block
    let mut t_1 = Transaction::new(alice_verifying_key, bob_verifying_key, 3);
    t_1.sign(&alice_signing_key);
    let mut t_2 = Transaction::new(alice_verifying_key, bob_verifying_key, 10);
    t_2.sign(&alice_signing_key);
    let mut t_3 = Transaction::new(bob_verifying_key, alice_verifying_key, 8);
    t_3.sign(&bob_signing_key);
    let mut t_4 = Transaction::new(bob_verifying_key, alice_verifying_key, 1);
    t_4.sign(&bob_signing_key);
    let mut t_5 = Transaction::new(bob_verifying_key, alice_verifying_key, 2);
    t_5.sign(&bob_signing_key);

    // Blocks
    let b_0 = Block::new(0, Vec::from([t_0, t_1, t_2, t_3]), [0; 32]);
    let b_1 = Block::new(b_0.index+1, Vec::from([t_4, t_5]), b_0._hash().unwrap());
}

struct Block {
    index: u64,
    transactions: Vec<Transaction>,
    previous_hash: [u8; 32],
    timestamp: u128,
    nonce: u64,
    hash: Option<[u8; 32]>,
}

impl Block {
    fn new(index: u64, transactions: Vec<Transaction>, previous_hash: [u8; 32]) -> Block {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards!")
            .as_millis();
        let mut block = Block {
            index,
            transactions,
            previous_hash,
            timestamp,
            nonce: 0,
            hash: None,
        };

        block.hash = block._hash();
        block
    }

    fn _hash(&self) -> Option<[u8; 32]> {
        let block_bytes = self._to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&block_bytes);
        Some(hasher.finalize().into())
    }

    fn _to_bytes(&self) -> Vec<u8> {
        //todo!("Use serde to serialize instead");
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.index.to_be_bytes());
        for transaction in &self.transactions {
            bytes.extend_from_slice(&transaction._hash());
        }
        bytes.extend_from_slice(&self.previous_hash);
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());

        bytes
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
        //todo!("Use serde to serialize instead");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.sender.to_sec1_bytes());
        bytes.extend_from_slice(&self.receiver.to_sec1_bytes());
        bytes.extend_from_slice(&self.amount.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes
    }
}
