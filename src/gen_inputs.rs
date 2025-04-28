// generate inputs for the main.rs
use std::env;
use std::fs;
use std::io::{self, Write};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Sha256, Digest};
use rand::Rng;
use rand::rngs::OsRng;

// Helper: decode Base64URL (with '-'→'+', '_'→'/', padding)
fn base64_url_decode(s: &str) -> Vec<u8> {
    let mut b64 = s.replace('-', "+").replace('_', "/");
    let pad = (4 - b64.len() % 4) % 4;
    for _ in 0..pad { b64.push('='); }
    STANDARD.decode(&b64).expect("Invalid Base64URL")
}

// Helper: get top‑level JSON value for key
fn get_json_value<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pattern = format!("\"{}\":", key);
    let i = json.find(&pattern)?;
    let slice = &json[i + pattern.len()..].trim_start();
    if slice.starts_with('"') {
        // string
        let without_first_quote = slice.strip_prefix('"')?;
        let end = without_first_quote.find('"')?;
        Some(&slice[..=end+1])
    } else {
        // number, bool, or literal until comma/bracket
        let end = slice.find(&[',', '}'][..]).unwrap_or(slice.len());
        Some(slice[..end].trim_end_matches(','))
    }
}

fn main() -> io::Result<()> {
    // Get JWT filepath from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <jwt_file_path>", args[0]);
        std::process::exit(1);
    }
    let jwt_file_path = &args[1];
    
    // Read JWT from file
    let jwt_str = fs::read_to_string(jwt_file_path)?;
    let jwt_str = jwt_str.trim(); // Remove any whitespace
    let jwt_bytes = jwt_str.as_bytes();
    
    // Split JWT
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        eprintln!("Invalid JWT format: expected 3 parts");
        std::process::exit(1);
    }
    
    // Decode payload
    let payload_bytes = base64_url_decode(parts[1]);
    let payload_str = String::from_utf8(payload_bytes).expect("Invalid UTF-8 in payload");
    
    // Extract nonce (if it exists)
    let nonce_raw = get_json_value(&payload_str, "nonce");
    
    // Generate ephemeral data
    let mut rng = OsRng;
    let mut eph_pk = [0u8; 32];
    let mut eph_rand = [0u8; 32];
    rng.fill(&mut eph_pk);
    
    if let Some(nonce_quoted) = nonce_raw {
        // Nonce exists in JWT - need to make eph_pk and eph_rand match
        let nonce_unquoted = &nonce_quoted[1..nonce_quoted.len()-1];
        let nonce_bytes = base64_url_decode(nonce_unquoted);
        
        // Simple approach: fix eph_pk, vary eph_rand until hash matches
        // For demo only - in practice this is computationally infeasible
        let max_attempts = 10000;
        let mut found = false;
        
        for _ in 0..max_attempts {
            rng.fill(&mut eph_rand);
            
            let mut hasher = Sha256::new();
            hasher.update(&eph_pk);
            hasher.update(&eph_rand);
            let hash_result = hasher.finalize();
            
            if hash_result.as_slice() == nonce_bytes.as_slice() {
                found = true;
                break;
            }
        }
        
        if !found {
            eprintln!("Warning: Could not find matching eph_rand. Using nonce bytes directly.");
            // Just use the nonce as both eph_pk and eph_rand for testing
            if nonce_bytes.len() >= 32 {
                eph_pk.copy_from_slice(&nonce_bytes[0..32]);
                eph_rand.copy_from_slice(&nonce_bytes[0..32]);
            }
        }
    } else {
        // No nonce in JWT - just use random values
        rng.fill(&mut eph_rand);
    }
    
    // Generate random pepper
    let mut pepper = [0u8; 32];
    rng.fill(&mut pepper);
    
    // Extract epoch from iat if available, or use current time
    let epoch = match get_json_value(&payload_str, "iat") {
        Some(iat_str) => iat_str.parse::<u64>().unwrap_or_else(|_| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        }),
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    // Output all inputs as u64 little-endian hexstrings
    // 1. JWT length
    println!("{:016x}", jwt_bytes.len() as u64);
    
    // 2. JWT bytes (as u8s)
    for &byte in jwt_bytes {
        println!("{:016x}", byte as u64);
    }
    
    // 3. RSA exponent (65537)
    println!("{:016x}", 65537u64);
    
    // 4. Ephemeral values (eph_pk, eph_rand, pepper)
    // Each is 32 bytes, written as 4 u64s in little-endian format
    for buffer in [&eph_pk, &eph_rand, &pepper] {
        for i in 0..4 {
            let mut u64_val: u64 = 0;
            for j in 0..8 {
                u64_val |= (buffer[i*8 + j] as u64) << (j * 8);
            }
            println!("{:016x}", u64_val);
        }
    }
    
    // 5. Epoch
    println!("{:016x}", epoch);
    
    Ok(())
}
