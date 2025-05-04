use k256::{
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    elliptic_curve::rand_core::OsRng,
    schnorr::SigningKey,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt,
    sync::mpsc,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug)]
pub enum Message {
    NewTransaction(Transaction),
    NewBlock(Block),
}

pub struct Node {
    pub id: String,
    pub blockchain: Blockchain,
    pub tx: mpsc::Sender<Message>,
    pub tx_pool: HashMap<[u8; 32], Transaction>,
    signing_key: SigningKey,         // extract it to a Wallet struct later
    pub verifying_key: VerifyingKey, // extract it to a Wallet struct later
}

impl Node {
    pub fn new(id: String, genesis: Block, tx: mpsc::Sender<Message>) -> Node {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        Node {
            id,
            blockchain: Blockchain::new(genesis.clone()),
            tx,
            tx_pool: HashMap::new(),
            signing_key,
            verifying_key,
        }
    }

    pub fn create_and_broadcast_transaction(
        &self,
        receiver_key: VerifyingKey,
        amount: u64,
    ) -> Result<(), mpsc::SendError<Message>> {
        let mut transaction = Transaction::new(self.verifying_key, receiver_key, amount);
        transaction.sign(&self.signing_key);
        self.tx.send(Message::NewTransaction(transaction.clone()))
    }

    pub fn mine_and_broadcast_block(&self) -> Result<(), mpsc::SendError<Message>>  {
        let new_block = Block::new(
            self.blockchain.chain.last().unwrap().index + 1,
            self.tx_pool.values().cloned().collect(),
            self.blockchain.chain.last().unwrap().hash.unwrap(),
        );
        self.tx.send(Message::NewBlock(new_block.clone()))
    }

    pub fn process_messages(&mut self, rx: &mpsc::Receiver<Message>) {
        loop {
            match rx.try_recv() {
                Ok(message) => {
                    match message {
                        Message::NewTransaction(transaction) => {
                            if transaction.verify() {
                                println!("Verified transaction:\n{}", transaction);
                                let entry = self.tx_pool.entry(transaction.hash());
                                match entry {
                                    std::collections::hash_map::Entry::Vacant(e) => {
                                        e.insert(transaction.clone());
                                        println!("Transaction inserted.");
                                    }
                                    std::collections::hash_map::Entry::Occupied(_) => {
                                        println!("Transaction already exists.");
                                    }
                                }
                            } else {
                                println!("Transaction verification failed: {}", transaction);
                            }
                        }
                        Message::NewBlock(block) => {
                            println!("Received new block: {}", block.index);
                            match self.blockchain.add_block(block.clone()) {
                                Ok(_) => {
                                    // Remove common transactions (both in Alice pool & the block)
                                    for transaction in block.transactions.iter() {
                                        println!("{:?}", transaction.hash());
                                        if let Some(value) =
                                            self.tx_pool.remove(&transaction.hash())
                                        {
                                            println!(
                                                "Remove transaction {:?} from Alice's pool",
                                                value.hash()
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    println!("[Alice]Error {} while adding block.", e)
                                }
                            }
                        }
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {
                    break;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    println!("Channel disconnected");
                    break;
                }
            }
        }
    }
}

pub struct Blockchain {
    pub chain: Vec<Block>,
}

impl Blockchain {
    pub fn new(genesis: Block) -> Blockchain {
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

#[derive(Clone, Debug)]
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
            bytes.extend_from_slice(&transaction.hash());
        }
        bytes.extend_from_slice(&self.previous_hash);
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());

        bytes
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let max_lenght = 6;
        write!(
            f,
            "Block[{}]: Hash[{}], Prev[{}], {} txs, Nonce[{}]",
            self.index,
            format_bytes(&self.hash.unwrap_or_default(), max_lenght),
            format_bytes(&self.previous_hash, max_lenght),
            self.transactions.len(),
            self.nonce
        )
    }
}

#[derive(Clone, Debug)]
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
                let hash = self.hash();
                self.sender.verify(&hash, signature).is_ok()
            }
            None => false,
        }
    }

    pub fn sign(&mut self, signing_key: &SigningKey) {
        // Verify if the signing_key is owned by sender
        if VerifyingKey::from(signing_key) == self.sender {
            let hash = self.hash();
            self.signature = Some(signing_key.sign(&hash));
        }
    }

    pub fn hash(&self) -> [u8; 32] {
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

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let max_lenght = 6;
        write!(
            f,
            "Tr[{}]: {} => {} (Amount: {})",
            format_bytes(&self.hash(), max_lenght),
            format_bytes(&self.sender.to_sec1_bytes(), max_lenght),
            format_bytes(&self.receiver.to_sec1_bytes(), max_lenght),
            self.amount
        )
    }
}

fn format_bytes(bytes: &[u8], max_lenght: usize) -> String {
    let hex_string: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    if hex_string.len() > max_lenght {
        format!(
            "{}...{}",
            &hex_string[..max_lenght],
            &hex_string[hex_string.len() - max_lenght..]
        )
    } else {
        hex_string
    }
}
