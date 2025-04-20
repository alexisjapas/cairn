use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Blockchain {
    pub chain: Vec<Block>,
}

impl Blockchain {
    pub fn new() -> Blockchain {
        let genesis = Block::new(0, Vec::new(), [0u8; 32]);
        Blockchain {
            chain: Vec::from([genesis]),
        }
    }

    pub fn add_block(&mut self, new_block: Block) -> Result<(), String> {
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

pub struct Block {
    pub index: u64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: [u8; 32],
    pub timestamp: u128,
    pub nonce: u64,
    pub hash: Option<[u8; 32]>,
}

impl Block {
    pub fn new(index: u64, transactions: Vec<Transaction>, previous_hash: [u8; 32]) -> Block {
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

pub struct Transaction {
    sender: VerifyingKey,
    receiver: VerifyingKey,
    amount: u64,
    timestamp: u128,
    signature: Option<Signature>,
}

impl Transaction {
    pub fn new(sender: VerifyingKey, receiver: VerifyingKey, amount: u64) -> Transaction {
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

    pub fn verify(&self) -> bool {
        match &self.signature {
            Some(signature) => {
                let hash = self._hash();
                self.sender.verify(&hash, signature).is_ok()
            }
            None => false,
        }
    }

    pub fn sign(&mut self, signing_key: &SigningKey) {
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
