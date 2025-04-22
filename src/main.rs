use k256::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::rand_core::OsRng,
};
use std::{sync::mpsc, collections::HashMap};

mod cairn;

fn main() {
    // MESSAGES
    let (tx, rx) = mpsc::channel::<cairn::Message>();
    let tx_alice = tx.clone();
    let tx_bob = tx.clone();

    // NODES
    // Alice's Node
    let mut node_alice_blockchain = cairn::Blockchain::new();
    let mut node_alice_tx_pool: HashMap<[u8; 32], cairn::Transaction> = HashMap::new();
    // Alice's keys
    let alice_signing_key = SigningKey::random(&mut OsRng);
    let alice_verifying_key = VerifyingKey::from(&alice_signing_key);

    // Bob's Node
    let mut node_bob_blockchain = cairn::Blockchain::new();
    let mut node_bob_tx_pool: HashMap<[u8; 32], cairn::Transaction> = HashMap::new();
    // Bob's keys
    let bob_signing_key = SigningKey::random(&mut OsRng);
    let bob_verifying_key = VerifyingKey::from(&bob_signing_key);

    // TRANSACTIONS: batch 1
    // Generate & sign transactions
    let mut t_0 = cairn::Transaction::new(alice_verifying_key, bob_verifying_key, 1);
    t_0.sign(&alice_signing_key);
    let mut t_1 = cairn::Transaction::new(alice_verifying_key, bob_verifying_key, 3);
    t_1.sign(&alice_signing_key);
    let mut t_2 = cairn::Transaction::new(alice_verifying_key, bob_verifying_key, 10);
    t_2.sign(&alice_signing_key);
    let mut t_3 = cairn::Transaction::new(bob_verifying_key, alice_verifying_key, 8);
    t_3.sign(&bob_signing_key);
    
    // Send transactions
    tx_alice.send(cairn::Message::NewTransaction(t_0.clone())).unwrap();
    tx_alice.send(cairn::Message::NewTransaction(t_1.clone())).unwrap();

    // Read
    loop {
        match rx.try_recv() {
            Ok(message) => {
                // Alice node
                match message {
                    cairn::Message::NewTransaction(transaction) => {
                        if transaction.verify() {
                            println!("Verified transaction:\n{:?}", transaction);
                            let entry = node_bob_tx_pool.entry(transaction.hash());
                            match entry {
                                std::collections::hash_map::Entry::Vacant(e) => {
                                    e.insert(transaction.clone());
                                    println!("Transaction inserted.");
                                },
                                std::collections::hash_map::Entry::Occupied(_) => {
                                    println!("Transaction already exists.");
                                }
                            }
                            let entry = node_bob_tx_pool.entry(transaction.hash());
                            match entry {
                                std::collections::hash_map::Entry::Vacant(e) => {
                                    e.insert(transaction.clone());
                                    println!("Transaction inserted.");
                                },
                                std::collections::hash_map::Entry::Occupied(_) => {
                                    println!("Transaction already exists.");
                                }
                            }
                        } else {
                            println!("Transaction verification failed: {:?}", transaction);
                        }
                    },
                    cairn::Message::NewBlock(block) => {
                        println!("Received new block: {}", block.index);
                        // todo process the block
                    }
                }
            },
            Err(mpsc::TryRecvError::Empty) => {
                break;
            },
            Err(mpsc::TryRecvError::Disconnected) => {
                println!("Channel disconnected");
                break;
            }
        }
    }

    // TRANSACTIONS: batch 2
    let mut t_4 = cairn::Transaction::new(bob_verifying_key, alice_verifying_key, 1);
    t_4.sign(&bob_signing_key);
    let mut t_5 = cairn::Transaction::new(bob_verifying_key, alice_verifying_key, 2);
    t_5.sign(&bob_signing_key);
    
    
}
