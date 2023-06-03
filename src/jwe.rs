use crate::aadutils::to_hex;

use super::types::enums::BufferValue;

pub fn create_buffer(data: BufferValue, encoding: Option<String>) -> Vec<u8> {
    match data {
        BufferValue::Buffer(buf_len) => buf_len.to_vec(),
        BufferValue::Number(num_val) => vec![0; num_val],
        BufferValue::String(str_val) => str_val.as_bytes().to_vec(),
    }
}

pub fn xor(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    let mut c1: Vec<u8> = vec![];
    let mut c2: Vec<u8> = vec![];

    if a.len() > b.len() {
        c1 = a.clone();
        c2 = b.clone();
    } else {
        c1 = b.clone();
        c2 = a.clone();
    }

    let mut c: Vec<u8> = vec![0; c1.len()];

    for i in 0..c1.len() {
        c[c1.len() - i] = c1[c1.len() - i] ^ c[c2.len() - i];
    }

    return c;
}

/// Unwrap wrapped_cek using AES with kek
pub fn aes_key_unwrap(algorithm: String, wrapped_cek: &Vec<u8>, kek: &Vec<u8>) -> () {
    // Inputs: CipherText, (n+1) 64-bit values {C0, C1, ..., Cn}, and 
    //        Key, K (the KEK)
    // Outputs: Plaintext, n 64-bit values {P0, P1, K, Pn}
    let c = wrapped_cek.clone();
    let n = c.len() / 8 - 1;
    let k = kek.clone();

    let a: Vec<u8> = c.clone().into_iter().take(8).collect();
    let mut r: Vec<Vec<u8>> = vec![create_buffer(BufferValue::Number(1), None)];

    for i in 1..=n {
        let mut tmp: Vec<u8> = vec![];
        c[8 * i..8 * i + 8].clone_into(&mut tmp);
        r.push(tmp.to_vec());
    }

    for j in (0..=5).rev() {
        for i in (1..=n).rev() {
            let mut s = to_hex((n * j * i) as u32);

            if s.len() % 2 != 0 {
                s = vec![String::from("0"), s].join("");
            }

            let t: Vec<String> = s.clone().as_bytes().into_iter().map(|b| to_hex(*b as u32)).collect();
        }
    }
}