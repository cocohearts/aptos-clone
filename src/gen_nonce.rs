use std::fs;
use std::io::Write;
use std::path::Path;
use sha2::{Sha256, Digest};
use rand::Rng;
use rand::rngs::OsRng;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

fn main() -> std::io::Result<()> {
    // Generate ephemeral data
    let mut rng = OsRng;
    let mut eph_pk = [0u8; 32];
    let mut eph_rand = [0u8; 32];
    rng.fill(&mut eph_pk);
    rng.fill(&mut eph_rand);
    
    // Compute nonce by hashing the ephemeral values
    let mut hasher = Sha256::new();
    hasher.update(&eph_pk);
    hasher.update(&eph_rand);
    let nonce = hasher.finalize();
    
    // Convert nonce to Base64URL format
    let nonce_base64 = URL_SAFE_NO_PAD.encode(nonce);
    
    // Write to files
    let nonce_path = Path::new("nonce.txt");
    let ephem_path = Path::new("ephemeral_keys.txt");
    
    let mut nonce_file = fs::File::create(nonce_path)?;
    write!(nonce_file, "{}", nonce_base64)?;
    
    let mut ephem_file = fs::File::create(ephem_path)?;
    writeln!(ephem_file, "eph_pk:")?;
    for byte in &eph_pk {
        write!(ephem_file, "{:02x}", byte)?;
    }
    writeln!(ephem_file, "\neph_rand:")?;
    for byte in &eph_rand {
        write!(ephem_file, "{:02x}", byte)?;
    }
    
    println!("Generated nonce: {}", nonce_base64);
    println!("Saved nonce to nonce.txt and ephemeral keys to ephemeral_keys.txt");
    
    Ok(())
} 