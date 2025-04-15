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
    // Tests
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!")
        .as_millis();

    // Initialize the blockchain
    let mut blockchain = Blockchain::new();

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

    // Add valid blocks
    let b_1 = Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([t_0, t_1, t_2, t_3]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    println!("Adding b_1: {:?}", blockchain.add_block(b_1));
    let b_2 = Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([t_4, t_5]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    println!("Adding b_2: {:?}", blockchain.add_block(b_2));

    // Add invalid blocks
    // Index error
    let b_3 = Block::new(
        12,
        Vec::from([]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    println!("Adding b_3: {:?}", blockchain.add_block(b_3));
    // Transaction error
    let mut t_6 = Transaction::new(bob_verifying_key, alice_verifying_key, 8462);
    t_6.sign(&alice_signing_key);
    let b_4 = Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([t_6]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    println!("Adding b_4: {:?}", blockchain.add_block(b_4));
    // Hashes link mismatch
    let b_5 = Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([]),
        blockchain.chain.first().unwrap().hash.unwrap(),
    );
    println!("Adding b_5: {:?}", blockchain.add_block(b_5));
    // Time goes backwards
    let mut b_6 = Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    b_6.timestamp = timestamp;
    println!("Adding b_6: {:?}", blockchain.add_block(b_6));
    // Hash has been manipulated
    let mut b_7 = Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    b_7.hash = Some([0u8; 32]);
    println!("Adding b_7: {:?}", blockchain.add_block(b_7));
}

struct Blockchain {
    chain: Vec<Block>,
}

impl Blockchain {
    fn new() -> Blockchain {
        let genesis = Block::new(0, Vec::new(), [0u8; 32]);
        Blockchain {
            chain: Vec::from([genesis]),
        }
    }

    fn add_block(&mut self, new_block: Block) -> Result<(), String> {
        // Get last block (the chain is never empty, as genesis is initialized at creation)
        let last_block = self.chain.last().unwrap();

        // Verify conformity
        let transactions_conformity = new_block.verify_transactions();
        if new_block.index != last_block.index + 1 {
            return Err("Block verification failed: indexes mismatch.".to_string());
        } else if new_block.timestamp <= last_block.timestamp {
            return Err("Block verification failed: time goes backwards.".to_string());
        } else if new_block.previous_hash != last_block.hash.unwrap() {
            return Err("Block verification failed: hashes link mismatch.".to_string());
        } else if new_block.hash.unwrap() != new_block._hash().unwrap() {
            return Err("Block verification failed: hash error.".to_string());
        } else if transactions_conformity.is_err() {
            return transactions_conformity;
        } else {
            println!("Block {} added succesfully!", new_block.index);
            self.chain.push(new_block);
            Ok(())
        }
    }
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

    fn verify_transactions(&self) -> Result<(), String> {
        for transaction in self.transactions.iter() {
            if !transaction.verify() {
                return Err("Block verification failed: error in transactions.".to_string());
            }
        }
        Ok(())
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
