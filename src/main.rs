// src/main.rs
use std::vec::Vec;
use openvm::io::{read, reveal_u32};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use openvm_sha256_guest::sha256;
use crypto_bigint::{U2048, U4096, NonZero};
use crypto_bigint::Encoding;

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

// Enhanced RSA modular exponentiation for 2048-bit numbers using crypto-bigint
fn rsa_verify_complete(sig: &[u8], exponent: u32, message_hash: &[u8]) -> bool {
    // Hardcoded RSA modulus (2048-bit) - this would normally come from a certificate
    // Convert our array of 32 u64 values into a U2048
    let modulus_array = [
        0x3515, 0x8092, 0x4290, 0x6848, 0x9261, 0x9735, 0x9613, 0x4573,
        0x9861, 0x7519, 0x9509, 0x6805, 0x1224, 0x7147, 0x3058, 0x6148,
        0x1061, 0x3028, 0x9059, 0x3137, 0x0501, 0x9293, 0x8982, 0x2229,
        0x9105, 0x3169, 0x4422, 0x0690, 0x0624, 0x9151, 0x6422, 0x7906,
    ];
    
    // Convert the array to bytes in big-endian format
    let mut modulus_bytes = [0u8; 256];
    for (i, &value) in modulus_array.iter().enumerate() {
        let byte_idx = 255 - i * 8;
        for j in 0..8 {
            modulus_bytes[byte_idx - j] = ((value as u64 >> (8 * (7 - j))) & 0xFF) as u8;
        }
    }
    
    // Create U2048 from byte arrays
    let modulus = U2048::from_be_slice(&modulus_bytes);
    
    // Convert signature to U2048
    let mut sig_bytes = [0u8; 256];
    let offset = 256 - sig.len();
    sig_bytes[offset..].copy_from_slice(sig);
    let sig_val = U2048::from_be_slice(&sig_bytes);
    
    // Verify exponent is 65537
    assert!(exponent == 65537, "Invalid exponent");
    
    // Create non-zero modulus for modular exponentiation
    let non_zero_modulus = NonZero::new(modulus).expect("Modulus cannot be zero");
    
    // Implement modular exponentiation with fixed exponent 65537
    let result = mod_65537(&sig_val, &non_zero_modulus);
    
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
    let result_bytes = result.to_be_bytes();
    
    // Compare the expected PKCS1v15 padded hash with our decrypted result
    expected.as_slice() == &result_bytes[..]
}

// Implementation of modular exponentiation with fixed exponent 65537
fn mod_65537(base: &U2048, modulus: &NonZero<U2048>) -> U2048 {
    // Implement b^65537 mod n
    // 65537 = 2^16 + 1 in binary: 10000000000000001
    
    // Initial value: base mod modulus
    let mut result = base.clone().rem(modulus);
    let big_modulus = U4096::from_be_slice(&modulus.as_ref().to_be_bytes());
    let big_modulus_non_zero = NonZero::new(big_modulus).expect("Big modulus cannot be zero");
    
    // Store original value for the final multiplication
    let base_mod = result;
    
    // Square 16 times (for 2^16)
    for _ in 0..16 {
        // Square (multiply by itself) and reduce
        let result1: U4096 = (result).mul(&result);
        result = U2048::from_be_slice(&result1.rem(&big_modulus_non_zero).to_be_bytes()[32..]);
    }
    
    // Final multiply: result * base_mod mod modulus (for the +1 in 2^16+1)
    let final_mul: U4096 = (result).mul(&base_mod);
    U2048::from_be_slice(&final_mul.rem(&big_modulus_non_zero).to_be_bytes()[32..])
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
    let rsa_exponent: u32 = read(); // Should be 65537 (0x10001)
    
    // Ephemeral data
    // Helper function to read a U256 value from input
    fn read_u256_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        
        for i in 0..4 {
            let mut word = read::<u64>();
            
            // Extract 8 bytes from the u64 using modulo, in big-endian order
            for j in 0..8 {
                // For big-endian, place bytes from end to start
                bytes[i * 8 + 7 - j] = (word % 256) as u8;
                word /= 256;
            }
        }
        bytes
    }
    
    let eph_pk = read_u256_bytes();
    let eph_rand = read_u256_bytes();
    let pepper = read_u256_bytes();
    
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
    let payload_json = &signed_data[dot1+1..];

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
    // uid
    let uid_raw = get_json_value(payload_json, "sub");
    let uid = if uid_raw.starts_with('"') {
        assert!(uid_raw.ends_with('"'), "uid not string");
        str_to_bytes(&uid_raw[1..uid_raw.len()-1])
    } else {
        str_to_bytes(uid_raw)
    };
    // Verify that iat is not too far from current epoch
    let iat: u64 = get_json_value(payload_json, "iat").parse().expect("iat not number");
    const MAX_JWT_AGE_SECONDS: u64 = 86400; // 24 hours
    let time_diff = if epoch > iat { epoch - iat } else { iat - epoch };
    assert!(time_diff <= MAX_JWT_AGE_SECONDS, "JWT is too old or from the future");
    // email_verified
    let ev = get_json_value(payload_json, "email_verified");
    assert!(ev == "True", "email_verified must be true");

    // --- RSA signature (RS256) verification ---
    // Compute SHA256(header.payload)
    let hash = sha256(signed_data.as_bytes());
    // Use RSA verification with built-in modulus
    let sig_valid = rsa_verify_complete(&sig_bytes, rsa_exponent, &hash);
    assert!(sig_valid, "RSA signature verification failed");

    // --- Nonce hash check ---
    let nonce_raw = get_json_value(payload_json, "nonce");
    assert!(nonce_raw.starts_with('"') && nonce_raw.ends_with('"'), "nonce not string");
    let nonce_bytes = base64_url_decode(&nonce_raw[1..nonce_raw.len()-1]);
    let nonce_data = [&eph_pk[..], &eph_rand[..]].concat();
    let nonce_hash = sha256(&nonce_data);
    assert!(nonce_hash.as_slice() == nonce_bytes.as_slice(), "nonce mismatch");

    // --- addr_seed & public_inputs_hash ---
    let pkey_data = [&uid[..], &aud[..], &pepper[..]].concat();
    let pkey = sha256(&pkey_data);
    // Convert the SHA-256 hash (32 bytes) to [u32; 8]
    let mut pkey_u32 = [0u32; 8];
    for (i, value) in pkey_u32.iter_mut().enumerate() {
        let start = i * 4;
        *value = u32::from_be_bytes([
            pkey[start], pkey[start + 1], pkey[start + 2], pkey[start + 3]
        ]);
    }

    // Reveal the last 5 u32s as public inputs
    for (offset, &value) in pkey_u32[3..8].iter().enumerate() {
        reveal_u32(value, offset - 3);
    }
}