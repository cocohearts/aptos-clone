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
use openvm::io::{read, reveal_u64};
use base64::{decode, encode_config};
use openvm_bigint_guest::U256;
use openvm_sha256_guest::sha256;
use openvm_poseidon2_air::Poseidon;

// Helper: decode Base64URL (with '-'→'+', '_'→'/', padding)
fn base64_url_decode(s: &str) -> Vec<u8> {
    let mut b64 = s.replace('-', "+").replace('_', "/");
    let pad = (4 - b64.len() % 4) % 4;
    for _ in 0..pad { b64.push('='); }
    decode(&b64).expect("Invalid Base64URL")
}

// Helper: decimal string → U256
fn decimal_str_to_u256(s: &str) -> U256 {
    let mut acc = U256::ZERO;
    for &b in s.as_bytes() {
        let d = (b - b'0') as u64;
        acc = acc * U256::from_u64(10) + U256::from_u64(d);
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
        let end = slice[1..].find('"').expect("Unclosed string") + 1;
        &slice[..=end]
    } else {
        // number, bool, or literal until comma/bracket
        let end = slice.find(&[',', '}'][..]).unwrap_or(slice.len());
        &slice[..end].trim_end_matches(',')
    }
}

fn main() {
    // 1) Read JWT as length‑prefixed byte string
    let jwt_len: u64 = read();
    let mut jwt_bytes = Vec::with_capacity(jwt_len as usize);
    for _ in 0..jwt_len {
        jwt_bytes.push(read() as u8);
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
    let mut rsa_mod = U256::ZERO;
    for i in 0..32 {
        rsa_mod |= U256::from_u64(read() as u64) << U256::from_u64(8 * i);
    }
    // Read exponent
    let rsa_e: u32 = read();

    // Compute SHA256(signed_data)
    let hash = sha256(signed_data.as_bytes());

    // Deserialize signature bytes → U256
    let mut sig_val = U256::ZERO;
    for &b in sig_bytes.iter().rev() {
        sig_val = (sig_val << U256::from_u64(8)) | U256::from_u64(b as u64);
    }

    // Modular exponentiation: sig_val^e mod N
    let mut base = sig_val;
    while base >= rsa_mod {
        base = base - rsa_mod;
    }
    let mut result = U256::from_u64(1);
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
    for i in 0..key_bytes {
        let shift = 8 * (key_bytes - 1 - i);
        let byte = ((&decrypted >> shift) & U256::from_u64(0xFF)).as_u64() as u8;
        dec_bytes[i] = byte;
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

    // --- Nonce Poseidon check ---
    // Read ephemeral pk (32 bytes) & randomness (32 bytes) & epoch
    let mut eph_pk = U256::ZERO;
    for i in 0..32 {
        eph_pk |= U256::from_u64(read() as u64) << (8 * i);
    }
    let mut eph_rand = U256::ZERO;
    for i in 0..32 {
        eph_rand |= U256::from_u64(read() as u64) << (8 * i);
    }
    let epoch: u64 = read();

    // split pk hi/lo
    let pk_hi = eph_pk >> 128;
    let pk_lo = eph_pk & ((U256::from_u64(1)<<128) - U256::from_u64(1));
    let nonce_hash = Poseidon::hash(&[pk_hi, pk_lo, U256::from_u64(epoch), eph_rand]);

    // to bytes (big-endian)
    let mut nh_bytes = [0u8;32];
    for i in 0..32 {
        let shift = 8 * (31 - i);
        nh_bytes[i] = ((&nonce_hash >> shift) & U256::from_u64(0xFF)).as_u64() as u8;
    }
    let nh_b64 = {
        let mut tmp = nh_bytes.to_vec();
        base64::encode_config(&tmp, base64::URL_SAFE_NO_PAD)
    };
    assert!(nh_b64 == nonce, "nonce mismatch");

    // --- addr_seed & public_inputs_hash ---
    // hash aud, iss into field elems
    let aud_h = sha256(aud.as_bytes());
    let mut aud_elem = U256::ZERO;
    for &b in aud_h.iter().rev() {
        aud_elem = (aud_elem << 8) | U256::from_u64(b as u64);
    }
    let iss_h = sha256(iss.as_bytes());
    let mut iss_elem = U256::ZERO;
    for &b in iss_h.iter().rev() {
        iss_elem = (iss_elem << 8) | U256::from_u64(b as u64);
    }

    let addr_seed = Poseidon::hash(&[uid, aud_elem, iss_elem]);
    let pub_inputs = Poseidon::hash(&[iss_elem, aud_elem]);

    // reveal public_inputs_hash (4 chunks)
    let mut pi = pub_inputs;
    for i in 0..4 {
        let chunk = (&pi >> (64 * i)) & U256::from_u64(u64::MAX);
        reveal_u64(chunk.as_u64(), i as u32);
    }
    // reveal addr_seed (next 4)
    let mut asd = addr_seed;
    for i in 0..4 {
        let chunk = (&asd >> (64 * i)) & U256::from_u64(u64::MAX);
        reveal_u64(chunk.as_u64(), 4 + i as u32);
    }
}