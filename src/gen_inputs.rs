// generate inputs for the main.rs
use std::env;
use std::fs;
use std::io;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::Rng;
use rand::rngs::OsRng;
use serde_json::json;
use sha2::{Sha256, Digest};

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

// Helper: format an integer as hex with 0x01 prefix
// Handles different integer sizes based on the actual type
fn format_as_hex<T: Into<u128> + Copy>(value: T) -> String {
    use std::mem::size_of;
    
    // Get the byte size from the type itself
    let byte_size = size_of::<T>();
    let value_u128: u128 = value.into();
    
    // Format directly to hex
    let hex = format!("{:0width$x}", value_u128, width = byte_size * 2);
    
    // Collect bytes (pairs of hex characters) and reverse their order
    let reversed = hex.chars().rev().collect::<Vec<_>>();
    let reversed_str: String = reversed.iter().collect();
    format!("0x01{}", reversed_str)
}

fn main() -> io::Result<()> {
    // Get JWT filepath from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <jwt_file_path> [nonce_file_path]", args[0]);
        std::process::exit(1);
    }
    let jwt_file_path = &args[1];
    
    // Optional nonce file path, defaults to "nonce.txt"
    let nonce_file_path = if args.len() > 2 { &args[2] } else { "nonce.txt" };
    
    // Read JWT from file
    let jwt_str = fs::read_to_string(jwt_file_path)?;
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
    
    // Read ephemeral values from nonce file if it exists
    let mut eph_pk = [0u8; 32];
    let mut eph_rand = [0u8; 32];
    
    match fs::read_to_string(nonce_file_path) {
        Ok(nonce_base64) => {
            // We have a nonce file, read it and use its values directly
            println!("Using nonce from file: {}", nonce_base64.trim());
            
            // The gen_nonce.rs program should have also saved ephemeral_keys.txt
            if let Ok(ephem_keys) = fs::read_to_string("ephemeral_keys.txt") {
                // Simple parsing of the hex values
                if let Some(pk_start) = ephem_keys.find("eph_pk:") {
                    if let Some(rand_start) = ephem_keys.find("eph_rand:") {
                        let pk_hex = &ephem_keys[pk_start+7..rand_start].trim();
                        let rand_hex = &ephem_keys[rand_start+9..].trim();
                        
                        for i in 0..32 {
                            if i*2+1 < pk_hex.len() {
                                let hex_byte = &pk_hex[i*2..i*2+2];
                                eph_pk[i] = u8::from_str_radix(hex_byte, 16).unwrap_or(0);
                            }
                            
                            if i*2+1 < rand_hex.len() {
                                let hex_byte = &rand_hex[i*2..i*2+2];
                                eph_rand[i] = u8::from_str_radix(hex_byte, 16).unwrap_or(0);
                            }
                        }
                    }
                }
            } else {
                eprintln!("Warning: ephemeral_keys.txt not found, using random values");
                let mut rng = OsRng;
                rng.fill(&mut eph_pk);
                rng.fill(&mut eph_rand);
            }
        },
        Err(_) => {
            eprintln!("Warning: Nonce file not found, using random ephemeral values");
            // Generate ephemeral data
            let mut rng = OsRng;
            rng.fill(&mut eph_pk);
            rng.fill(&mut eph_rand);
        }
    }
    
    // Generate pepper as hash(epkey, secret) where secret = 76
    let secret: u8 = 76;
    let mut hasher = Sha256::new();
    hasher.update(eph_pk);
    hasher.update([secret]);
    let pepper_hash = hasher.finalize();
    
    // Convert the hash result to a 32-byte array
    let mut pepper = [0u8; 32];
    pepper.copy_from_slice(&pepper_hash);
    
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
    
    // Create an array to hold all the inputs in the required format
    let mut input_array = Vec::new();
    
    // 1. JWT length as u64 in little-endian with 0x01 prefix
    input_array.push(format_as_hex(jwt_bytes.len() as u64));

    // 2. JWT bytes (as u8s)
    for &byte in jwt_bytes {
        input_array.push(format_as_hex(byte));
    }
    
    // 3. RSA exponent (65537)
    // Convert 65537 (0x10001) to little-endian bytes and format
    let exponent: u32 = 65537;
    input_array.push(format_as_hex(exponent));
    
    // 4. Ephemeral values (eph_pk, eph_rand, pepper)
    // Each is 64 bytes, written as 2 u128s in little-endian format
    for buffer in [&eph_pk, &eph_rand, &pepper] {
        for i in 0..2 {
            let mut u128_val: u128 = 0;
            for j in 0..16 {
                u128_val |= (buffer[i*16 + j] as u128) << (j * 8);
            }
            input_array.push(format_as_hex(u128_val));
        }
    }
    
    // 5. Epoch
    input_array.push(format_as_hex(epoch));
    
    // Create the final JSON structure
    let json_data = json!({
        "input": input_array
    });
    
    // Write to input.json
    let json_string = serde_json::to_string_pretty(&json_data)?;
    fs::write("input.json", json_string)?;
    println!("Created input.json successfully");
    
    Ok(())
}

