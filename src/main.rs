use k256::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::rand_core::OsRng,
};
use std::{collections::HashMap, sync::mpsc};

mod cairn;

fn main() {
    // MESSAGES
    debug_step_message("Initialize messaging system");
    let (tx, rx) = mpsc::channel::<cairn::Message>();

    // NODES
    debug_step_message("Initialize nodes");
    // Genesis block
    let genesis = cairn::Block::new(0, Vec::new(), [0u8; 32]);
    let mut node_alice = cairn::Node::new(String::from("N_ALICE"), genesis.clone(), tx.clone());
    let mut node_bob = cairn::Node::new(String::from("N_BOB"), genesis.clone(), tx.clone());

    // TRANSACTIONS: batch 1
    debug_step_message("Generate & send transactions: batch 1");
    // Generate & sign transactions
    node_alice.create_and_broadcast_transaction(node_bob.verifying_key, 10);
    node_alice.create_and_broadcast_transaction(node_bob.verifying_key, 21);
    node_alice.create_and_broadcast_transaction(node_bob.verifying_key, 3);
    node_bob.create_and_broadcast_transaction(node_alice.verifying_key, 12);
    node_bob.create_and_broadcast_transaction(node_alice.verifying_key, 5);

    // READ & SAVE
    process_messages(
        &rx,
        &mut node_alice_blockchain,
        &mut node_alice_tx_pool,
        &mut node_bob_blockchain,
        &mut node_bob_tx_pool,
    );

    // MINING: phase 1
    debug_step_message("Mining: phase 1");
    // Alice
    node_alice.mine_and_broadcast_block();

    // TRANSACTIONS: batch 2
    debug_step_message("Generate & send transactions: batch 2");
    let mut t_4 = cairn::Transaction::new(bob_verifying_key, alice_verifying_key, 1);
    t_4.sign(&bob_signing_key);
    let mut t_5 = cairn::Transaction::new(bob_verifying_key, alice_verifying_key, 2);
    t_5.sign(&bob_signing_key);
    tx_bob
        .send(cairn::Message::NewTransaction(t_4.clone()))
        .unwrap();
    tx_bob
        .send(cairn::Message::NewTransaction(t_5.clone()))
        .unwrap();

    process_messages(
        &rx,
        &mut node_alice_blockchain,
        &mut node_alice_tx_pool,
        &mut node_bob_blockchain,
        &mut node_bob_tx_pool,
    );

    // MINING: phase 2
    debug_step_message("Mining: phase 2");
    // Bob
    let new_block = cairn::Block::new(
        node_bob_blockchain.chain.last().unwrap().index + 1,
        node_bob_tx_pool.values().cloned().collect(),
        node_bob_blockchain.chain.last().unwrap().hash.unwrap(),
    );
    tx_bob
        .send(cairn::Message::NewBlock(new_block.clone()))
        .unwrap();

    // READ & SAVE
    process_messages(
        &rx,
        &mut node_alice_blockchain,
        &mut node_alice_tx_pool,
        &mut node_bob_blockchain,
        &mut node_bob_tx_pool,
    );
}


fn process_messages(
    rx: &mpsc::Receiver<cairn::Message>,
    node_a_blockchain: &mut cairn::Blockchain,
    node_a_tx_pool: &mut HashMap<[u8; 32], cairn::Transaction>,
    node_b_blockchain: &mut cairn::Blockchain,
    node_b_tx_pool: &mut HashMap<[u8; 32], cairn::Transaction>,
) {
    loop {
        match rx.try_recv() {
            Ok(message) => {
                match message {
                    cairn::Message::NewTransaction(transaction) => {
                        if transaction.verify() {
                            println!("Verified transaction:\n{}", transaction);
                            let entry = node_b_tx_pool.entry(transaction.hash());
                            match entry {
                                std::collections::hash_map::Entry::Vacant(e) => {
                                    e.insert(transaction.clone());
                                    println!("Transaction inserted.");
                                }
                                std::collections::hash_map::Entry::Occupied(_) => {
                                    println!("Transaction already exists.");
                                }
                            }
                            let entry = node_a_tx_pool.entry(transaction.hash());
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
                    cairn::Message::NewBlock(block) => {
                        println!("Received new block: {}", block.index);
                        match node_a_blockchain.add_block(block.clone()) {
                            Ok(_) => {
                                // Remove common transactions (both in Alice pool & the block)
                                for transaction in block.transactions.iter() {
                                    println!("{:?}", transaction.hash());
                                    if let Some(value) = node_a_tx_pool.remove(&transaction.hash())
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
                        match node_b_blockchain.add_block(block.clone()) {
                            Ok(_) => {
                                // Remove common transactions (both in Bob pool & the block)
                                for transaction in block.transactions.iter() {
                                    println!("{:?}", transaction.hash());
                                    if let Some(value) = node_b_tx_pool.remove(&transaction.hash())
                                    {
                                        println!(
                                            "Remove transaction {:?} from Bob's pool",
                                            value.hash()
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                println!("[Bob]Error {} while adding block.", e)
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

fn debug_step_message(title: &str) {
    println!("\n{}", "#".repeat(title.len() + 3));
    println!("# {}", title);
}
