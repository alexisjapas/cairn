use sha2::{Sha256, Digest};


fn main() {
    let mut hasher = Sha256::new();
    let message = "Hello, world!";
    
    hasher.update(message.as_bytes());
    let result = hasher.finalize();
    
    println!("{} => {:x}", message, result);
}
