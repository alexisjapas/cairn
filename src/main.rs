use k256::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::rand_core::OsRng,
};
use std::time::{SystemTime, UNIX_EPOCH};

mod cairn;

fn main() {
    // Tests
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!")
        .as_millis();

    // Initialize the blockchain
    let mut blockchain = cairn::Blockchain::new();

    // Alice keys
    let alice_signing_key = SigningKey::random(&mut OsRng);
    let alice_verifying_key = VerifyingKey::from(&alice_signing_key);

    // Bob keys
    let bob_signing_key = SigningKey::random(&mut OsRng);
    let bob_verifying_key = VerifyingKey::from(&bob_signing_key);

    // New transaction from alice to bob
    let mut t_0 = cairn::Transaction::new(alice_verifying_key, bob_verifying_key, 1);

    // Sign the transaction
    t_0.sign(&alice_signing_key);

    // Verify the transaction
    match t_0.verify() {
        true => println!("Transaction is legit!"),
        false => println!("Transaction has been falsified!"),
    }

    // Other transactions to add to the block
    let mut t_1 = cairn::Transaction::new(alice_verifying_key, bob_verifying_key, 3);
    t_1.sign(&alice_signing_key);
    let mut t_2 = cairn::Transaction::new(alice_verifying_key, bob_verifying_key, 10);
    t_2.sign(&alice_signing_key);
    let mut t_3 = cairn::Transaction::new(bob_verifying_key, alice_verifying_key, 8);
    t_3.sign(&bob_signing_key);
    let mut t_4 = cairn::Transaction::new(bob_verifying_key, alice_verifying_key, 1);
    t_4.sign(&bob_signing_key);
    let mut t_5 = cairn::Transaction::new(bob_verifying_key, alice_verifying_key, 2);
    t_5.sign(&bob_signing_key);

    // Add valid blocks
    let b_1 = cairn::Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([t_0, t_1, t_2, t_3]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    println!("Adding b_1: {:?}", blockchain.add_block(b_1));
    let b_2 = cairn::Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([t_4, t_5]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    println!("Adding b_2: {:?}", blockchain.add_block(b_2));

    // Add invalid blocks
    // Index error
    let b_3 = cairn::Block::new(
        12,
        Vec::from([]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    println!("Adding b_3: {:?}", blockchain.add_block(b_3));
    // Transaction error
    let mut t_6 = cairn::Transaction::new(bob_verifying_key, alice_verifying_key, 8462);
    t_6.sign(&alice_signing_key);
    let b_4 = cairn::Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([t_6]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    println!("Adding b_4: {:?}", blockchain.add_block(b_4));
    // Hashes link mismatch
    let b_5 = cairn::Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([]),
        blockchain.chain.first().unwrap().hash.unwrap(),
    );
    println!("Adding b_5: {:?}", blockchain.add_block(b_5));
    // Time goes backwards
    let mut b_6 = cairn::Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    b_6.timestamp = timestamp;
    println!("Adding b_6: {:?}", blockchain.add_block(b_6));
    // Hash has been manipulated
    let mut b_7 = cairn::Block::new(
        blockchain.chain.last().unwrap().index + 1,
        Vec::from([]),
        blockchain.chain.last().unwrap().hash.unwrap(),
    );
    b_7.hash = Some([0u8; 32]);
    println!("Adding b_7: {:?}", blockchain.add_block(b_7));
}
