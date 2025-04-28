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
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use openvm_sha256_guest::sha256;

// Helper: decode Base64URL (with '-'→'+', '_'→'/', padding)
fn base64_url_decode(s: &str) -> Vec<u8> {
    let mut b64 = s.replace('-', "+").replace('_', "/");
    let pad = (4 - b64.len() % 4) % 4;
    for _ in 0..pad { b64.push('='); }
    STANDARD.decode(&b64).expect("Invalid Base64URL")
}

// Helper: decimal string → U256
fn decimal_str_to_u256(s: &str) -> u64 {
    let mut acc = 0;
    for &b in s.as_bytes() {
        let d = (b - b'0') as u64;
        acc = acc * 10 + d;
    }
    acc
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

fn main() {
    // 1) Read JWT as length‑prefixed byte string
    let jwt_len: u64 = read();
    let mut jwt_bytes = Vec::with_capacity(jwt_len as usize);
    for _ in 0..jwt_len {
        jwt_bytes.push(read::<u64>() as u8);
    }
    let jwt_str = core::str::from_utf8(&jwt_bytes).expect("Invalid UTF-8 JWT");

    // 2) Split off signature (base64url)
    let dot2 = jwt_str.rfind('.').expect("Missing signature '.'");
    let signed_data = &jwt_str[..dot2];
    let sig_b64 = &jwt_str[dot2+1..];
    let sig_bytes = base64_url_decode(sig_b64);

    // 3) Split header.payload → decode payload JSON
    let dot1 = signed_data.find('.').expect("Missing payload '.'");
    let payload_b64 = &signed_data[dot1+1..];
    let payload_bytes = base64_url_decode(payload_b64);
    let payload_json = core::str::from_utf8(&payload_bytes).expect("Bad payload UTF-8");

    // --- RSA signature (RS256) verification ---
    // Read RSA modulus (32 bytes default for 2048‑bit)
    let mut rsa_mod = 0;
    for i in 0..32 {
        rsa_mod |= read::<u64>() << (8 * i);
    }
    // Read exponent
    let rsa_e: u32 = read();

    // Compute SHA256(signed_data)
    let hash = sha256(signed_data.as_bytes());

    // Deserialize signature bytes → U256
    let mut sig_val = 0;
    for &b in sig_bytes.iter().rev() {
        sig_val = (sig_val << 8) | b as u64;
    }

    // Modular exponentiation: sig_val^e mod N
    let mut base = sig_val;
    base &= rsa_mod;
    let mut result = 1;
    let mut exp = rsa_e;
    while exp > 0 {
        if exp & 1 == 1 {
            let product = result * base;
            let quotient = product / rsa_mod;
            result = product - (quotient * rsa_mod);
        }
        let product = base * base;
        let quotient = product / rsa_mod;
        base = product - (quotient * rsa_mod);
        exp >>= 1;
    }
    let decrypted = result;

    // Build expected PKCS#1 v1.5 padded digest
    let der_prefix: [u8;19] = [
        0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
        0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
    ];
    let key_bytes = 256;
    let mut expect_t = Vec::with_capacity(key_bytes);
    expect_t.extend_from_slice(&[0x00, 0x01]);
    let ps_len = key_bytes - hash.len() - der_prefix.len() - 3;
    expect_t.extend(core::iter::repeat(0xFF).take(ps_len));
    expect_t.push(0x00);
    expect_t.extend_from_slice(&der_prefix);
    expect_t.extend_from_slice(&hash);

    // Compare decrypted bytes
    let mut dec_bytes = [0u8;256];
    for (i, byte_ref) in dec_bytes.iter_mut().enumerate().take(key_bytes) {
        let shift = 8 * (key_bytes - 1 - i);
        *byte_ref = ((decrypted >> shift) & 0xFF) as u8;
    }
    assert!(dec_bytes == expect_t.as_slice(), "RSA signature invalid");

    // --- JSON structural checks ---
    assert!(payload_json.starts_with('{') && payload_json.ends_with('}'), "Bad JSON");
    assert!(!payload_json[1..payload_json.len()-1].contains('{'), "Nested object");
    assert!(!payload_json.contains('['), "Arrays disallowed");

    // --- Extract & validate each field ---
    // aud
    let aud_raw = get_json_value(payload_json, "aud");
    assert!(aud_raw.starts_with('"') && aud_raw.ends_with('"'), "aud not string");
    let aud = &aud_raw[1..aud_raw.len()-1];

    // iss
    let iss_raw = get_json_value(payload_json, "iss");
    assert!(iss_raw.starts_with('"') && iss_raw.ends_with('"'), "iss not string");
    let iss = &iss_raw[1..iss_raw.len()-1];

    // uid
    let uid_raw = get_json_value(payload_json, "uid");
    let uid = if uid_raw.starts_with('"') {
        decimal_str_to_u256(&uid_raw[1..uid_raw.len()-1])
    } else {
        decimal_str_to_u256(uid_raw)
    };

    // iat
    let iat_raw = get_json_value(payload_json, "iat");
    let iat: u64 = iat_raw.parse().expect("iat not number");

    // nonce
    let nonce_raw = get_json_value(payload_json, "nonce");
    assert!(nonce_raw.starts_with('"') && nonce_raw.ends_with('"'), "nonce not string");
    let nonce = &nonce_raw[1..nonce_raw.len()-1];

    // email_verified
    let ev = get_json_value(payload_json, "email_verified");
    assert!(ev == "true", "email_verified must be true");

    // extra
    let extra = get_json_value(payload_json, "extra");
    assert!(!extra.starts_with('{') && !extra.starts_with('['), "extra must be primitive");

    // --- Nonce hash check ---
    // Read ephemeral pk (32 bytes) & randomness (32 bytes) & epoch
    let eph_pk_low: u128 = read::<u128>();
    let eph_pk_high: u128 = read::<u128>();
    
    let eph_rand_low: u128 = read::<u128>();
    let eph_rand_high: u128 = read::<u128>();
    
    let epoch: u64 = read();
    
    // Verify that iat is not too far from current epoch
    const MAX_JWT_AGE_SECONDS: u64 = 86400; // 24 hours
    let time_diff = if epoch > iat { epoch - iat } else { iat - epoch };
    assert!(time_diff <= MAX_JWT_AGE_SECONDS, "JWT is too old or from the future");
    
    // Convert to bytes and hash with sha256
    let mut to_hash = Vec::new();
    to_hash.extend_from_slice(&eph_pk_high.to_le_bytes());
    to_hash.extend_from_slice(&eph_pk_low.to_le_bytes());
    to_hash.extend_from_slice(&epoch.to_le_bytes());
    to_hash.extend_from_slice(&eph_rand_high.to_le_bytes());
    to_hash.extend_from_slice(&eph_rand_low.to_le_bytes());
    let nonce_hash = sha256(&to_hash);

    // Hash bytes directly
    let nh_b64 = {
        URL_SAFE_NO_PAD.encode(nonce_hash)
    };
    assert!(nh_b64 == nonce, "nonce mismatch");

    // --- addr_seed & public_inputs_hash ---
    // hash aud, iss into field elems
    let aud_h = sha256(aud.as_bytes());
    let iss_h = sha256(iss.as_bytes());
    
    // Combine and hash for addr_seed
    let mut addr_seed_data = Vec::new();
    addr_seed_data.extend_from_slice(&uid.to_le_bytes());
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