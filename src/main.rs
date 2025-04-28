// // src/main.rs
// use openvm::io::{read, reveal_u32};

// fn main() {
//     let n: u64 = read();
//     let mut a: u64 = 0;
//     let mut b: u64 = 1;
//     for _ in 0..n {
//         let c: u64 = a.wrapping_add(b);
//         a = b;
//         b = c;
//     }
//     reveal_u32(a as u32, 0);
//     reveal_u32((a >> 32) as u32, 1);
// }

extern crate alloc;
use alloc::vec::Vec;
use openvm::io::read;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use openvm_sha256_guest::sha256;
use core::cmp::Ordering;

// Pair for representing u256 as [high, low]
struct Pair<T> {
    high: T,
    low: T,
}

// Helper: decode Base64URL (with '-'→'+', '_'→'/', padding)
fn base64_url_decode(s: &str) -> Vec<u8> {
    let mut b64 = s.replace('-', "+").replace('_', "/");
    let pad = (4 - b64.len() % 4) % 4;
    for _ in 0..pad { b64.push('='); }
    STANDARD.decode(&b64).expect("Invalid Base64URL")
}

// Helper: decimal string → byte array
fn str_to_bytes(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

// Helper: get top‑level JSON value for key
fn get_json_value<'a>(json: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{}\":", key);
    let i = json.find(&pattern).expect("Missing key");
    let slice = &json[i + pattern.len()..].trim_start();
    if slice.starts_with('"') {
        // string
        let without_first_quote = slice.strip_prefix('"').expect("Missing opening quote");
        let end = without_first_quote.find('"').expect("Unclosed string");
        &slice[..=end+1]
    } else {
        // number, bool, or literal until comma/bracket
        let end = slice.find(&[',', '}'][..]).unwrap_or(slice.len());
        slice[..end].trim_end_matches(',')
    }
}

// Enhanced RSA modular exponentiation for 2048-bit numbers (32 limbs)
fn rsa_verify_complete(sig: &[u8], modulus: &[u64; 32], exponent: u32, message_hash: &[u8]) -> bool {
    // Convert signature to big integer representation
    let mut sig_val = [0u64; 32];
    for i in 0..sig.len().min(256) {
        let limb_idx = i / 8;
        let byte_pos = i % 8;
        sig_val[limb_idx] |= (sig[sig.len() - 1 - i] as u64) << (byte_pos * 8);
    }
    assert!(exponent == 65537, "Invalid exponent");
    
    // Implement full modular exponentiation for large integers
    // This is a simplified approach - in production, use a dedicated big integer library
    let mut result = [0u64; 32];
    result[0] = 1; // Set to 1
    
    // For each bit in the exponent (65537 = 10000000000000001 in binary)
    // We can optimize for e=65537 by performing 16 squarings and 1 multiplication
    
    // Store sig_val for squaring operations
    let mut base = sig_val;
    
    // First, handle the least significant bit (which is 1 for e=65537)
    result = base;
    
    // Perform 16 squarings to handle the upper bit
    for _ in 0..16 {
        base = square_mod(&base, modulus);
    }
    
    // Multiply result by the final square to complete exponentiation
    result = multiply_mod(&result, &base, modulus);
    
    // Build expected PKCS#1 v1.5 padded digest
    let der_prefix: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    ];
    
    // Create expected padded message (2048 bits = 256 bytes)
    let key_bytes = 256;
    let mut expected = Vec::with_capacity(key_bytes);
    expected.extend_from_slice(&[0x00, 0x01]);
    let ps_len = key_bytes - message_hash.len() - der_prefix.len() - 3;
    expected.extend(core::iter::repeat(0xFF).take(ps_len));
    expected.push(0x00);
    expected.extend_from_slice(&der_prefix);
    expected.extend_from_slice(message_hash);
    
    // Convert result to bytes and compare
    let mut result_bytes = [0u8; 256];
    for (i, limb) in result.iter().enumerate() {
        for j in 0..8 {
            let byte_idx = i * 8 + j;
            if byte_idx < 256 {
                result_bytes[255 - byte_idx] = ((limb >> (j * 8)) & 0xFF) as u8;
            }
        }
    }
    
    // Compare the expected PKCS1v15 padded hash with our decrypted result
    expected.as_slice() == &result_bytes[..]
}

fn square_mod(base: &[u64; 32], modulus: &[u64; 32]) -> [u64; 32] {
    multiply_mod(base, base, modulus)
}

fn multiply_mod(a: &[u64; 32], b: &[u64; 32], modulus: &[u64; 32]) -> [u64; 32] {
    // Simplified modular multiplication
    // In a real implementation, use a proper big integer library
    
    // Perform schoolbook multiplication
    let mut product = [0u64; 64]; // Twice the limbs for full product
    
    for i in 0..32 {
        let mut carry = 0u64;
        for j in 0..32 {
            let t = product[i + j] as u128 + (a[i] as u128 * b[j] as u128) + carry as u128;
            product[i + j] = t as u64;
            carry = (t >> 64) as u64;
        }
        product[i + 32] = carry;
    }
    
    // Perform modular reduction (simplified)
    // This is a basic approach - real implementation would use optimized reduction
    let mut remainder = product;
    
    for i in (32..64).rev() {
        if remainder[i] != 0 {
            // Find approximate quotient
            let q = remainder[i];
            
            // Subtract q * modulus from remainder (shifted by i-32 positions)
            let mut borrow = 0i128;
            for j in 0..32 {
                if i - 32 + j < 64 {
                    let t = remainder[i - 32 + j] as i128 - (q as i128 * modulus[j] as i128) - borrow;
                    remainder[i - 32 + j] = t as u64;
                    borrow = if t < 0 { 1 } else { 0 };
                }
            }
        }
    }
    
    // Copy lower 32 limbs as result
    let mut result = remainder[..32].try_into().unwrap();
    
    // Ensure result is less than modulus
    while compare_ge(&result, modulus) {
        // Subtract modulus from result
        let mut borrow = 0i128;
        for i in 0..32 {
            let t = result[i] as i128 - modulus[i] as i128 - borrow;
            result[i] = t as u64;
            borrow = if t < 0 { 1 } else { 0 };
        }
    }
    
    result
}

fn compare_ge(a: &[u64; 32], b: &[u64; 32]) -> bool {
    for i in (0..32).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Greater => return true,
            Ordering::Less => return false,
            Ordering::Equal => continue,
        }
    }
    true // Equal is also greater-or-equal
}

fn main() {
    // Read all inputs first
    // JWT data
    let jwt_len: u64 = read();
    let mut jwt_bytes = Vec::with_capacity(jwt_len as usize);
    for _ in 0..jwt_len {
        jwt_bytes.push(read::<u8>());
    }
    
    // RSA data
    let mut rsa_modulus = [0u64; 32];
    rsa_modulus.iter_mut().for_each(|val| *val = read::<u64>());
    let rsa_exponent: u32 = read(); // Should be 65537 (0x10001)
    
    // Ephemeral data
    let eph_pk = Pair {
        high: read::<u128>(),
        low: read::<u128>(),
    };
    
    let eph_rand = Pair {
        high: read::<u128>(),
        low: read::<u128>(),
    };
    
    let epoch: u64 = read();
    
    // Process JWT
    let jwt_str = core::str::from_utf8(&jwt_bytes).expect("Invalid UTF-8 JWT");

    // Split off signature (base64url)
    let dot2 = jwt_str.rfind('.').expect("Missing signature '.'");
    let signed_data = &jwt_str[..dot2];
    let sig_b64 = &jwt_str[dot2+1..];
    let sig_bytes = base64_url_decode(sig_b64);

    // Split header.payload → decode payload JSON
    let dot1 = signed_data.find('.').expect("Missing payload '.'");
    let payload_b64 = &signed_data[dot1+1..];
    let payload_bytes = base64_url_decode(payload_b64);
    let payload_json = core::str::from_utf8(&payload_bytes).expect("Bad payload UTF-8");

    // --- RSA signature (RS256) verification ---
    // Compute SHA256(signed_data)
    let hash = sha256(signed_data.as_bytes());

    // Use enhanced RSA verification with full modulus
    let sig_valid = rsa_verify_complete(&sig_bytes, &rsa_modulus, rsa_exponent, &hash);
    assert!(sig_valid, "RSA signature verification failed");

    // --- JSON structural checks ---
    assert!(payload_json.starts_with('{') && payload_json.ends_with('}'), "Bad JSON");
    assert!(!payload_json[1..payload_json.len()-1].contains('{'), "Nested object");
    assert!(!payload_json.contains('['), "Arrays disallowed");

    // --- Extract & validate each field ---
    // aud
    let aud_raw = get_json_value(payload_json, "aud");
    assert!(aud_raw.starts_with('"') && aud_raw.ends_with('"'), "aud not string");
    let aud = str_to_bytes(&aud_raw[1..aud_raw.len()-1]);

    // iss
    let iss_raw = get_json_value(payload_json, "iss");
    assert!(iss_raw.starts_with('"') && iss_raw.ends_with('"'), "iss not string");
    let iss = &iss_raw[1..iss_raw.len()-1];

    // uid
    let uid_raw = get_json_value(payload_json, "sub");
    let uid = if uid_raw.starts_with('"') {
        assert!(uid_raw.ends_with('"'), "uid not string");
        str_to_bytes(&uid_raw[1..uid_raw.len()-1])
    } else {
        str_to_bytes(uid_raw)
    };

    // iat
    let iat: u64 = get_json_value(payload_json, "iat").parse().expect("iat not number");

    // nonce
    let nonce_raw = get_json_value(payload_json, "nonce");
    assert!(nonce_raw.starts_with('"') && nonce_raw.ends_with('"'), "nonce not string");
    let nonce_str = &nonce_raw[1..nonce_raw.len()-1];
    let nonce_bytes = base64_url_decode(nonce_str);

    // email_verified
    let ev = get_json_value(payload_json, "email_verified");
    assert!(ev == "True", "email_verified must be true");

    // extra
    let extra = get_json_value(payload_json, "extra");
    assert!(!extra.starts_with('{') && !extra.starts_with('['), "extra must be primitive");

    // --- Nonce hash check ---
    // Verify that iat is not too far from current epoch
    const MAX_JWT_AGE_SECONDS: u64 = 86400; // 24 hours
    let time_diff = if epoch > iat { epoch - iat } else { iat - epoch };
    assert!(time_diff <= MAX_JWT_AGE_SECONDS, "JWT is too old or from the future");
    
    // Convert to bytes and hash with sha256
    let mut to_hash = Vec::new();
    to_hash.extend_from_slice(&eph_pk.high.to_le_bytes());
    to_hash.extend_from_slice(&eph_pk.low.to_le_bytes());
    to_hash.extend_from_slice(&epoch.to_le_bytes());
    to_hash.extend_from_slice(&eph_rand.high.to_le_bytes());
    to_hash.extend_from_slice(&eph_rand.low.to_le_bytes());
    let nonce_hash = sha256(&to_hash);

    // Compare hash bytes directly
    assert!(nonce_hash.as_slice() == nonce_bytes.as_slice(), "nonce mismatch");

    // --- addr_seed & public_inputs_hash ---
    // hash aud, iss into field elems
    let aud_h = sha256(&aud);
    let iss_h = sha256(iss.as_bytes());
    
    // Combine and hash for addr_seed
    let mut addr_seed_data = Vec::new();
    addr_seed_data.extend_from_slice(&uid);
    addr_seed_data.extend_from_slice(&aud_h);
    addr_seed_data.extend_from_slice(&iss_h);
    let addr_seed = sha256(&addr_seed_data);
    
    // Combine and hash for public inputs
    let mut public_inputs_data = Vec::new();
    public_inputs_data.extend_from_slice(&iss_h);
    public_inputs_data.extend_from_slice(&aud_h);
    let pub_inputs = sha256(&public_inputs_data);

    // reveal public_inputs_hash (4 chunks)
    for i in 0..4 {
        let start = i * 8;
        let mut chunk = 0u64;
        for j in 0..8 {
            if start + j < pub_inputs.len() {
                chunk |= (pub_inputs[start + j] as u64) << (8 * j);
            }
        }
        println!("public_input chunk {}: {}", i, chunk);
    }
    
    // reveal addr_seed (next 4)
    for i in 0..4 {
        let start = i * 8;
        let mut chunk = 0u64;
        for j in 0..8 {
            if start + j < addr_seed.len() {
                chunk |= (addr_seed[start + j] as u64) << (8 * j);
            }
        }
        println!("addr_seed chunk {}: {}", i, chunk);
    }
}