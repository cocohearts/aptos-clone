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
use crypto_bigint::{U2048, U4096, NonZero};
use crypto_bigint::Encoding;

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
fn format_as_hex(value: u64) -> String {
    // Always use 8 bytes (64 bits) for consistency
    let byte_size = 8;
    
    // Convert to byte array in little-endian order
    let mut bytes = Vec::with_capacity(byte_size);
    let mut remaining = value;
    
    for _ in 0..byte_size {
        bytes.push((remaining & 0xFF) as u8);
        remaining >>= 8;
    }
    
    // Format byte array as hex string
    let hex = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");
    
    format!("0x01{}", hex)
}

// Extract kid from JWT header
fn extract_kid_from_jwt(jwt_str: &str) -> String {
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        panic!("Invalid JWT format: expected 3 parts");
    }
    
    // Decode header
    let header_bytes = base64_url_decode(parts[0]);
    let header_str = String::from_utf8(header_bytes)
        .expect("Invalid UTF-8 in JWT header");
    
    // Extract kid
    let kid_raw = match get_json_value(&header_str, "kid") {
        Some(value) => value,
        None => panic!("JWT header missing 'kid' field")
    };
    
    if !kid_raw.starts_with('"') || !kid_raw.ends_with('"') {
        panic!("kid value not properly quoted in JWT header");
    }
    
    // Remove quotes from kid
    let kid = &kid_raw[1..kid_raw.len()-1];
    println!("Extracted kid from JWT: {}", kid);
    kid.to_string()
}

// Compute RSA quotients for the optimized verification
fn compute_rsa_quotients(sig: &[u8], kid: &str) -> Vec<U2048> {
    // Map kid to the corresponding modulus
    let modulus_base64 = if kid == "23f7a3583796f97129e5418f9b2136fcc0a96462" {
        "jb7Wtq9aDMpiXvHGCB5nrfAS2UutDEkSbK16aDtDhbYJhDWhd7vqWhFbnP0C_XkSxsqWJoku69y49EzgabEiUMf0q3X5N0pNvV64krviH2m9uLnyGP5GMdwZpjTXARK9usGgYZGuWhjfgTTvooKDUdqVQYvbrmXlblkM6xjbA8GnShSaOZ4AtMJCjWnaN_UaMD_vAXvOYj4SaefDMSlSoiI46yipFdggfoIV8RDg1jeffyre_8DwOWsGz7b2yQrL7grhYCvoiPrybKmViXqu-17LTIgBw6TDk8EzKdKzm33_LvxU7AKs3XWW_NvZ4WCPwp4gr7uw6RAkdDX_ZAn0TQ"
    } else if kid == "07b80a365428525f8bf7cd0846d74a8ee4ef3625" {
        "03Cww27F2O7JxB5Ji9iT9szfKZ4MK-iPzVpQkdLjCuGKfpjaCVAz9zIQ0-7gbZ-8cJRaSLfByWTGMIHRYiX2efdjz1Z9jck0DK9W3mapFrBPvM7AlRni4lPlwUigDd8zxAMDCheqyK3vCOLFW-1xYHt_YGwv8b0dP7rjujarEYlWjeppO_QMNtXdKdT9eZtBEcj_9ms9W0aLdCFNR5AAR3y0kLkKR1H4DW7vncB46rqCJLenhlCbcW0MZ3asqcjqBQ2t9QMRnY83Zf_pNEsCcXlKp4uOQqEvzjAc9ZSr2sOmd_ESZ_3jMlNkCZ4J41TuG-My5illFcW5LajSKvxD3w"
    } else {
        panic!("Unsupported kid: {}", kid);
    };
    
    // Decode the Base64URL encoded modulus
    let modulus_bytes = base64_url_decode(modulus_base64);
    println!("Modulus bytes length: {}", modulus_bytes.len());
    
    // Create U2048 from byte arrays
    let mut padded_modulus = [0u8; 256];
    let offset = 256 - modulus_bytes.len();
    padded_modulus[offset..].copy_from_slice(&modulus_bytes);
    println!("Modulus loaded for kid: {}", kid);
    
    // Convert signature to U2048
    let mut sig_bytes = [0u8; 256];
    let offset = 256 - sig.len();
    sig_bytes[offset..].copy_from_slice(sig);
    let sig_val = U2048::from_be_slice(&sig_bytes);

    let mut big_padded_modulus = [0u8; 512];
    big_padded_modulus[512 - modulus_bytes.len()..].copy_from_slice(&modulus_bytes);
    let big_modulus = U4096::from_be_slice(&big_padded_modulus);
    let big_non_zero_modulus = NonZero::new(big_modulus).expect("Big modulus cannot be zero");
    
    // Initial value: base mod modulus
    let mut result = sig_val;
    
    // Store original value for the final multiplication
    let base_mod = result;
    
    // Vector to store all quotients (16 from squaring + 1 from final mult)
    let mut quotients = Vec::with_capacity(17);
    
    println!("Computing quotients for modular exponentiation...");
    
    // Square 16 times (for 2^16)
    for i in 0..16 {
        // Square (multiply by itself)
        let result_squared: U4096 = result.mul(&result);
        
        // Compute quotient and remainder
        let (quotient, _) = result_squared.div_rem(&big_non_zero_modulus);
        let quotient_u2048 = U2048::from_be_slice(&quotient.to_be_bytes()[256..]);
        
        // Store quotient as U2048 (we only need the lower 256 bytes)
        quotients.push(quotient_u2048);
        
        // Update result to remainder
        let rem = result_squared.rem(&big_non_zero_modulus);
        let rem_u2048 = U2048::from_be_slice(&rem.to_be_bytes()[256..]);
        result = rem_u2048;
        
        println!("Quotient {} computed", i+1);
    }
    
    // Final multiply: result * base_mod
    let final_mul: U4096 = result.mul(&base_mod);
    
    // Get quotient for final multiplication
    let (final_quotient, _) = final_mul.div_rem(&big_non_zero_modulus);
    let final_quotient_u2048 = U2048::from_be_slice(&final_quotient.to_be_bytes()[256..]);
    quotients.push(final_quotient_u2048);
    println!("Final quotient computed");
    
    quotients
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
    
    // Extract kid from JWT header
    let kid = extract_kid_from_jwt(&jwt_str);
    
    // Extract signature from JWT for RSA verification
    let parts: Vec<&str> = jwt_str.split('.').collect();
    let sig_bytes = base64_url_decode(parts[2]);
    
    // Compute RSA quotients for optimized verification
    println!("Computing RSA quotients...");
    let quotients = compute_rsa_quotients(&sig_bytes, &kid);
    println!("Generated {} quotients", quotients.len());
    
    // Split JWT
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
        input_array.push(format_as_hex(byte as u64));
    }
    
    // 3. RSA exponent (65537)
    // Convert 65537 (0x10001) to little-endian bytes and format
    let exponent: u32 = 65537;
    input_array.push(format_as_hex(exponent as u64));
    
    // 4. Add the quotients (each as 32 u64 values since they're U2048)
    println!("Adding quotients to input array...");
    for (i, quotient) in quotients.iter().enumerate() {
        println!("Adding quotient {}", i+1);
        // Convert U2048 to 32 u64 values in little-endian format
        let quotient_bytes = quotient.to_be_bytes();
        for i in 0..32 {  // 256 bytes / 8 bytes per u64 = 32
            let mut u64_val: u64 = 0;
            for j in 0..8 {
                if i*8 + j < quotient_bytes.len() {
                    // Use little-endian format for u64 values to match read_u2048 in main.rs
                    u64_val |= (quotient_bytes[i*8 + j] as u64) << (j * 8);
                }
            }
            input_array.push(format_as_hex(u64_val));
        }
    }
    
    // 5. Ephemeral values (eph_pk, eph_rand, pepper)
    // Each is 32 bytes, written as 4 u64s in little-endian format
    for buffer in [&eph_pk, &eph_rand, &pepper] {
        for i in 0..4 {
            let mut u64_val: u64 = 0;
            for j in 0..8 {
                u64_val |= (buffer[i*8 + j] as u64) << (j * 8);
            }
            input_array.push(format_as_hex(u64_val));
        }
    }
    
    // 6. Epoch
    input_array.push(format_as_hex(epoch));
    
    // Create the final JSON structure
    let json_data = json!({
        "input": input_array
    });
    
    // Write to input.json
    let json_string = serde_json::to_string_pretty(&json_data)?;
    fs::write("input.json", json_string)?;
    println!("Created input.json successfully with all inputs including RSA quotients");
    
    Ok(())
}

