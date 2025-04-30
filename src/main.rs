// src/main.rs

use std::vec::Vec;
use openvm::io::{read, reveal_u32, println, print};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use openvm_sha256_guest::sha256;
use crypto_bigint::{U2048, U4096, NonZero, CheckedSub};
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

// Helper function to read a U4096 quotient from input
fn read_u2048() -> U2048 {
    // Read 32 u64 values (256 bytes / 8 bytes per u64 = 32)
    let mut bytes = [0u8; 256];
    
    for i in 0..32 {
        let mut word = read::<u64>();
        
        // Extract 8 bytes from the u64 using modulo, in big-endian order
        for j in 0..8 {
            bytes[i * 8 + j] = (word % 256) as u8;
            word /= 256;
        }
    }
    
    U2048::from_be_slice(&bytes)
}

// Enhanced RSA modular exponentiation for 2048-bit numbers using crypto-bigint
// Now with pre-computed quotients to avoid expensive divisions in zkVM
fn rsa_verify_complete(sig: &[u8], exponent: u32, message_hash: &[u8], kid: &str, quotients: &[U2048; 17]) -> bool {
    // Validate kid is one of the supported key IDs
    assert!(
        kid == "23f7a3583796f97129e5418f9b2136fcc0a96462" || 
        kid == "07b80a365428525f8bf7cd0846d74a8ee4ef3625",
        "Unsupported key ID (kid)"
    );
    
    // Map kid to the corresponding modulus
    let modulus_base64 = if kid == "23f7a3583796f97129e5418f9b2136fcc0a96462" {
        "jb7Wtq9aDMpiXvHGCB5nrfAS2UutDEkSbK16aDtDhbYJhDWhd7vqWhFbnP0C_XkSxsqWJoku69y49EzgabEiUMf0q3X5N0pNvV64krviH2m9uLnyGP5GMdwZpjTXARK9usGgYZGuWhjfgTTvooKDUdqVQYvbrmXlblkM6xjbA8GnShSaOZ4AtMJCjWnaN_UaMD_vAXvOYj4SaefDMSlSoiI46yipFdggfoIV8RDg1jeffyre_8DwOWsGz7b2yQrL7grhYCvoiPrybKmViXqu-17LTIgBw6TDk8EzKdKzm33_LvxU7AKs3XWW_NvZ4WCPwp4gr7uw6RAkdDX_ZAn0TQ"
    } else {
        "03Cww27F2O7JxB5Ji9iT9szfKZ4MK-iPzVpQkdLjCuGKfpjaCVAz9zIQ0-7gbZ-8cJRaSLfByWTGMIHRYiX2efdjz1Z9jck0DK9W3mapFrBPvM7AlRni4lPlwUigDd8zxAMDCheqyK3vCOLFW-1xYHt_YGwv8b0dP7rjujarEYlWjeppO_QMNtXdKdT9eZtBEcj_9ms9W0aLdCFNR5AAR3y0kLkKR1H4DW7vncB46rqCJLenhlCbcW0MZ3asqcjqBQ2t9QMRnY83Zf_pNEsCcXlKp4uOQqEvzjAc9ZSr2sOmd_ESZ_3jMlNkCZ4J41TuG-My5illFcW5LajSKvxD3w"
    };
    
    // Decode the Base64URL encoded modulus
    let modulus_bytes = base64_url_decode(modulus_base64);
    println("Modulus bytes length: ");
    println(modulus_bytes.len().to_string());
    
    // Create U2048 from byte arrays
    let mut padded_modulus = [0u8; 256];
    let offset = 256 - modulus_bytes.len();
    padded_modulus[offset..].copy_from_slice(&modulus_bytes);
    let modulus = U2048::from_be_slice(&padded_modulus);
    println("Modulus loaded for kid: ");
    println(kid);
    
    // Convert signature to U2048
    let mut sig_bytes = [0u8; 256];
    let offset = 256 - sig.len();
    sig_bytes[offset..].copy_from_slice(sig);
    let sig_val = U2048::from_be_slice(&sig_bytes);
    
    // Verify exponent is 65537
    assert!(exponent == 65537, "Invalid exponent");
    println("Exponent verified");
    
    // Create non-zero modulus for modular exponentiation
    let non_zero_modulus = NonZero::new(modulus).expect("Modulus cannot be zero");
    
    // Implement modular exponentiation with fixed exponent 65537 using provided quotients
    let result = mod_65537_with_quotients(&sig_val, &non_zero_modulus, quotients);
    println("Result calculated");

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
    println("Expected padded message calculated");
    
    // Convert result to bytes and compare
    let result_bytes = result.to_be_bytes();
    
    // Compare the expected PKCS1v15 padded hash with our decrypted result
    expected.as_slice() == &result_bytes[..]
}

// Implementation of modular exponentiation with fixed exponent 65537 using pre-computed quotients
fn mod_65537_with_quotients(base: &U2048, modulus: &NonZero<U2048>, quotients: &[U2048; 17]) -> U2048 {
    // Initial value: base mod modulus
    let mut result = base.clone().rem(modulus);
    
    // Store original value for the final multiplication
    let base_mod = result;

    println("Beginning exponentiation with quotients");
    
    // Square 16 times (for 2^16)
    for quotient in quotients.iter().take(16) {
        // Square (multiply by itself)
        let result_squared: U4096 = result.mul(&result);
        
        // We assume the quotient is correct and directly compute the remainder
        // The caller is responsible for providing valid quotients
        // In a real implementation, we would verify the quotients through a ZK proof
        let remainder = result_squared.checked_sub(&quotient.mul(modulus)).unwrap();
        
        // Extract the lower 256 bytes (U2048) from remainder
        let rem_bytes = &remainder.to_be_bytes()[256..];
        result = U2048::from_be_slice(rem_bytes);

        let mod_diff = modulus.checked_sub(&result).unwrap();
        assert!(mod_diff != U2048::ZERO, "Remainder is not less than modulus");
    }
    
    // Final multiply: result * base_mod
    let final_mul: U4096 = result.mul(&base_mod);
    
    // Get the provided final quotient
    let final_quotient = &quotients[16];
    let remainder = final_mul.checked_sub(&final_quotient.mul(modulus)).unwrap();
    let result_final = U2048::from_be_slice(&remainder.to_be_bytes()[256..]);
    let final_mod_diff = modulus.checked_sub(&result_final).unwrap();
    assert!(final_mod_diff != U2048::ZERO, "Remainder is not less than modulus");
    
    result_final
}

fn main() {
    // Read all inputs first
    // JWT data
    let jwt_len: u64 = read::<u64>();
    println("JWT length: ");
    println(jwt_len.to_string());
    let mut jwt_bytes = Vec::with_capacity(jwt_len as usize);
    for _ in 0..jwt_len {
        jwt_bytes.push(read::<u8>());
    }
    
    // RSA data
    println("RSA exponent: ");
    let rsa_exponent: u32 = read::<u32>(); // Should be 65537 (0x10001)
    println(rsa_exponent.to_string());
    
    // Read pre-computed quotients (17 of them - 16 for squaring + 1 for final multiply)
    println("Reading pre-computed quotients...");
    let mut quotients = [U2048::ZERO; 17];
    for quotient in quotients.iter_mut() {
        *quotient = read_u2048();
    }
    
    // Ephemeral data
    // Helper function to read a U256 value from input
    fn read_u256_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        
        for i in 0..4 {
            let mut word = read::<u64>();
            
            // Extract 8 bytes from the u64 using modulo, in big-endian order
            for j in 0..8 {
                // For big-endian, place bytes from end to start
                bytes[i * 8 + j] = (word % 256) as u8;
                word /= 256;
            }
        }
        bytes
    }
    
    let eph_pk = read_u256_bytes();
    println("eph_pk: ");
    println(STANDARD.encode(eph_pk));
    let eph_rand = read_u256_bytes();
    println("eph_rand: ");
    println(STANDARD.encode(eph_rand));
    let pepper = read_u256_bytes();
    println("pepper: ");
    println(STANDARD.encode(pepper));
    
    let epoch: u64 = read::<u64>();
    println("epoch: ");
    println(epoch.to_string());

    // Process JWT
    let jwt_str = core::str::from_utf8(&jwt_bytes).expect("Invalid UTF-8 JWT");
    println("jwt_str: ");
    println(jwt_str);
    let dot2 = jwt_str.rfind('.').expect("Missing signature '.'");
    let signed_str = &jwt_str[..dot2];
    let signed_data = &jwt_bytes[..dot2];
    let sig_bytes = base64_url_decode(&jwt_str[dot2+1..]);
    let dot1 = signed_str.find('.').expect("Missing payload '.'");
    let header_encoded = &signed_str[..dot1];
    let payload_encoded = &signed_str[dot1+1..];

    let header_decoded = base64_url_decode(header_encoded);
    let header_str = core::str::from_utf8(&header_decoded).expect("Invalid UTF-8 JWT");
    println("header: ");
    println(header_str);
    let payload_decoded = base64_url_decode(payload_encoded);
    let payload_str = core::str::from_utf8(&payload_decoded).expect("Invalid UTF-8 JWT");
    println("payload: ");
    println(payload_str);

    // --- JSON structural checks ---
    assert!(payload_str.starts_with('{') && payload_str.ends_with('}'), "Bad JSON");
    assert!(!payload_str[1..payload_str.len()-1].contains('{'), "Nested object");
    assert!(!payload_str.contains('['), "Arrays disallowed");
    // --- Extract & validate each field ---
    // aud
    let aud_raw = get_json_value(payload_str, "aud");
    assert!(aud_raw.starts_with('"') && aud_raw.ends_with('"'), "aud not string");
    let aud = str_to_bytes(&aud_raw[1..aud_raw.len()-1]);
    // iss
    let iss_raw = get_json_value(payload_str, "iss");
    assert!(iss_raw.starts_with('"') && iss_raw.ends_with('"'), "iss not string");
    // uid
    let uid_raw = get_json_value(payload_str, "sub");
    let uid = if uid_raw.starts_with('"') {
        assert!(uid_raw.ends_with('"'), "uid not string");
        str_to_bytes(&uid_raw[1..uid_raw.len()-1])
    } else {
        str_to_bytes(uid_raw)
    };
    // Verify that iat is not too far from current epoch
    let iat: u64 = get_json_value(payload_str, "iat").parse().expect("iat not number");
    const MAX_JWT_AGE_SECONDS: u64 = 86400; // 24 hours
    let time_diff = if epoch > iat { epoch - iat } else { iat - epoch };
    assert!(time_diff <= MAX_JWT_AGE_SECONDS, "JWT is too old or from the future");
    // email_verified
    let ev = get_json_value(payload_str, "email_verified");
    assert!(ev == "true", "email_verified must be true");
    println("JSON checks passed");

    // --- RSA signature (RS256) verification ---
    // Compute SHA256(header.payload)
    let hash = sha256(signed_data);
    println("signed hash calculated");
    
    // Extract kid from header
    let alg = get_json_value(header_str, "alg");
    assert!(alg == "\"RS256\"", "alg must be RS256");
    let typ = get_json_value(header_str, "typ");
    assert!(typ == "\"JWT\"", "typ must be JWT");
    let kid = get_json_value(header_str, "kid");
    assert!(kid.starts_with('"') && kid.ends_with('"'), "kid not string");
    let kid_str = &kid[1..kid.len()-1];
    println("Using kid: ");
    println(kid_str);
    
    // Use RSA verification with the specified kid and pre-computed quotients
    let sig_valid = rsa_verify_complete(&sig_bytes, rsa_exponent, &hash, kid_str, &quotients);
    assert!(sig_valid, "RSA signature verification failed");
    println("RSA signature verification passed");

    // --- Nonce hash check ---
    let nonce_raw = get_json_value(payload_str, "nonce");
    assert!(nonce_raw.starts_with('"') && nonce_raw.ends_with('"'), "nonce not string");
    let nonce_bytes = base64_url_decode(&nonce_raw[1..nonce_raw.len()-1]);
    let nonce_data = [&eph_pk[..], &eph_rand[..]].concat();
    let nonce_hash = sha256(&nonce_data);
    assert!(nonce_hash.as_slice() == nonce_bytes.as_slice(), "nonce mismatch");
    println("Nonce hash check passed");

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
    println("pkey_u32 hex: ");
    for i in 0..pkey_u32.len() {
        print(format!("{:08x}", pkey_u32[i]));
        if i < pkey_u32.len() - 1 {
            print(" ");
        }
    }
    println("");

    // Reveal the u32s as public inputs
    for (offset, &value) in pkey_u32[..].iter().enumerate() {
        reveal_u32(value, offset);
    }
}