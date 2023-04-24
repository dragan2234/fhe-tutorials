use std::ops::{BitAnd, ShlAssign, Shl, BitOr, Neg, BitXor};

use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint32};
use tfhe::prelude::*;

// H constants
const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// K constants
const K: &[u32] = &[
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// struct HCipers {
//     inner: GenericInteger<P>
// }

// #[derive(Clone)]
// struct U32Ct {
//     inner: [BoolCt; 32], // little endian
// }

struct InputCiphertext {
    inner: Vec<FheUint32>,
}

impl InputCiphertext {
    fn encrypt(x: Vec<u32>, client_key: &tfhe::ClientKey) -> Self {
        let inner = x.iter()
            .copied() // <- iter on u32 not &u32
            .map(|value| {
                FheUint32::try_encrypt(value, client_key).unwrap()
            }).collect();
        Self { inner }
    }
}

fn main() {
    use std::time::Instant;
    let now = Instant::now();
    {

    let hehe: Vec<u32> = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
].to_vec();

    let keke: Vec<u32> = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
].to_vec();

    let input_message = "RedBlockBlue";

    let padded_input = padded_input(input_message);

    let config = ConfigBuilder::all_disabled()
        .enable_default_uint32()
        .build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    let mut input_ciphertext = InputCiphertext::encrypt(padded_input, &client_key);

    let h_ciphertext = InputCiphertext::encrypt(hehe, &client_key);

    let k_ciphertext = InputCiphertext::encrypt(keke, &client_key);

    //1787555839

    // let res = rotate_left(h_ciphertext.inner.first().unwrap().clone() , 4);

    // let decr_res_or: u32 = res.decrypt(&client_key);


    // assert_eq!(decr_res_or, 3869285990u32);

    // let decrypted_result: u32 = input_ciphertext.inner.first().clone().unwrap().decrypt(&client_key);


    // let mut v = input_ciphertext.inner.first().clone().unwrap();

    // let mut e = k_ciphertext.inner.first().unwrap();

    // # In n<<d, last d bits are 0.
    // # To put first 3 bits of n at
    // # last, do bitwise or of n<<d
    // # with n >>(INT_BITS - d)
    // return (n << d)|(n >> (INT_BITS - d))
    // (v as FheUint32) <<= 2;

    // &v.bitshift
    // &v << 2;


    // let bitwised = (v << 2u32) | (v >> 30u32);


    // let decrypted_bitwised: u32 = bitwised.decrypt(&client_key);

    // assert_eq!(decrypted_bitwised, 1234538761);

    // assert_eq!(decrypted_result, 1382376514);

    // let decrypted_result_h: u32 = h_ciphertext.inner.first().unwrap().decrypt(&client_key);

    // assert_eq!(1779033703, decrypted_result_h);

    for i in 16..63 {
        let w_i_minus_2 = input_ciphertext.inner.get(i-2).unwrap();
        let w_i_minus_7 = input_ciphertext.inner.get(i-7).unwrap();
        let w_i_minus_15 = input_ciphertext.inner.get(i-15).unwrap();
        let w_i_minus_16 = input_ciphertext.inner.get(i-16).unwrap();

        let w_i = sigma_one(w_i_minus_2.clone()) + w_i_minus_7 + sigma_zero(w_i_minus_15.clone()) + w_i_minus_16;

        input_ciphertext.inner.push(w_i);
    }
    let mut T_1: FheUint32;
    let mut T_2: FheUint32;
    let mut a = h_ciphertext.inner.get(0).unwrap().clone();
    let mut b = h_ciphertext.inner.get(1).unwrap().clone();
    let mut c = h_ciphertext.inner.get(2).unwrap().clone();
    let mut d = h_ciphertext.inner.get(3).unwrap().clone();
    let mut e = h_ciphertext.inner.get(4).unwrap().clone();
    let mut f = h_ciphertext.inner.get(5).unwrap().clone();
    let mut g = h_ciphertext.inner.get(6).unwrap().clone();
    let mut h = h_ciphertext.inner.get(7).unwrap().clone();
    let mut ch_val: FheUint32;
    for i in 0..63 {
        ch_val = ch(e.clone(),f.clone(),g.clone());
        T_1 = h.clone() + capsigma_one(e.clone()) + ch_val.clone() + k_ciphertext.inner.get(i).unwrap().clone() + input_ciphertext.inner.get(i).unwrap().clone();
        T_2 = capsigma_zero(a.clone()) + maj(a.clone(),b.clone(),c.clone());
        h = g.clone();
        g = f.clone();
        f = e.clone();
        e = d.clone() + T_1.clone();
        d = c.clone();
        c = b.clone();
        b = a.clone();
        a = T_1.clone() + T_2.clone();
    }


    let first_32 = h_ciphertext.inner.get(0).unwrap().clone() + a.clone();
    let second_32 = h_ciphertext.inner.get(1).unwrap().clone() + b.clone();
    let third_32 = h_ciphertext.inner.get(2).unwrap().clone() + c.clone();
    let fourth_32 = h_ciphertext.inner.get(3).unwrap().clone() + d.clone();
    let fifth_32 = h_ciphertext.inner.get(4).unwrap().clone() + e.clone();
    let sixth_32 = h_ciphertext.inner.get(5).unwrap().clone() + f.clone();
    let seventh_32 = h_ciphertext.inner.get(6).unwrap().clone() + g.clone();
    let eight_32 = h_ciphertext.inner.get(7).unwrap().clone() + h.clone();

    let decrypted_first: u32 = first_32.decrypt(&client_key);
    let decrypted_second: u32 = second_32.decrypt(&client_key);
    let decrypted_third: u32 = third_32.decrypt(&client_key);
    let decrypted_fourth: u32 = fourth_32.decrypt(&client_key);
    let decrypted_fifth: u32 = fifth_32.decrypt(&client_key);
    let decrypted_sixth: u32 = sixth_32.decrypt(&client_key);
    let decrypted_seventh: u32 = seventh_32.decrypt(&client_key);
    let decrypted_eight: u32 = eight_32.decrypt(&client_key);

    println!("Decrypted First: {}", decrypted_first);
    println!("Decrypted Second: {}", decrypted_second);
    println!("Decrypted Third: {}", decrypted_third);
    println!("Decrypted Fourth: {}", decrypted_fourth);
    println!("Decrypted Fifth: {}", decrypted_fifth);
    println!("Decrypted Sixth: {}", decrypted_sixth);
    println!("Decrypted Seventh: {}", decrypted_seventh);
    println!("Decrypted Eight: {}", decrypted_eight);


    }

    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);

}

// Chat-GPT generated helper functions
fn print_u32_binary(v: &Vec<u32>) {
    for value in v.iter() {
        println!("{:032b}", value);
    }
}

fn string_to_u32_vector(s: &str) -> Vec<u32> {
    let mut result = Vec::new();
    let bytes = s.as_bytes();

    for i in (0..bytes.len()).step_by(4) {
        let slice_end = std::cmp::min(i + 4, bytes.len());
        let bytes_slice = &bytes[i..slice_end];
        let mut value_bytes = [0u8; 4];
        value_bytes[..bytes_slice.len()].copy_from_slice(bytes_slice);
        let value = u32::from_be_bytes(value_bytes);
        println!("My number is: {}", value);
        result.push(value);
    }

    result
}

fn split_into_8bit_vector(vec: &Vec<u32>) -> Vec<u8> {
    let mut result = Vec::new();
    for value in vec.iter() {
        for i in 0..4 {
            result.push(((value >> (24 - i * 8)) & 0xFF) as u8);
        }
    }
    result
}

fn replace_first_zero_byte(vec: &mut Vec<u8>) {
    for byte in vec.iter_mut() {
        if *byte == 0 {
            *byte = 0b10000000;
            break;
        }
    }
}

fn vec_u8_to_u32(input: &[u8]) -> Vec<u32> {
    assert_eq!(input.len() % 4, 0, "Input length must be a multiple of 4");
    let mut output = Vec::with_capacity(input.len() / 4);
    for i in (0..input.len()).step_by(4) {
        let byte_slice = &input[i..i + 4];
        let mut bytes = [0u8; 4];
        bytes[..byte_slice.len()].copy_from_slice(byte_slice);
        let value = u32::from_be_bytes(bytes);
        output.push(value);
    }
    output
}


fn padded_input(input_message: &str) -> Vec<u32> {
    // let input_message = "RedBlockBlue";

    let bit_length = input_message.as_bytes().len() * 8;
    println!("{:?}", bit_length);

    let mut result = string_to_u32_vector(input_message);

    for i in result.len()..15 {
        result.push(0u32);
    }
    result.push(bit_length as u32);
    println!("{:?}", result);

    let mut eight_bits = split_into_8bit_vector(&result.clone());

    println!("{:?}", eight_bits);

    replace_first_zero_byte(&mut eight_bits);

    println!("{:?}", eight_bits);

    let returned = vec_u8_to_u32(&eight_bits);

    println!("{:?}", returned);

    print_u32_binary(&returned);

    returned
}


fn ch(x: FheUint32, y: FheUint32, z: FheUint32) -> FheUint32 {
    let res = x.clone().bitand(y).bitxor(x.clone().neg().bitand(z));
    res 
}

fn maj(x: FheUint32, y: FheUint32, z: FheUint32) -> FheUint32 {
    let res = x.clone().bitand(y.clone()).bitxor(x.clone().bitand(z.clone())).bitxor(y.clone().bitand(z.clone()));
    res
}

fn capsigma_zero(x: FheUint32) -> FheUint32 {
    let mut first = rotate_right(x.clone(),2);

    let mut second = rotate_right(x.clone(),13);
    let mut third = rotate_right(x.clone(),22);

    let res = first.bitxor(second.clone()).bitxor(third.clone());

    res
}

fn capsigma_one(x: FheUint32) -> FheUint32 {
    let mut first = rotate_right(x.clone(),6);

    let mut second = rotate_right(x.clone(),11);
    let mut third = rotate_right(x.clone(),25);

    let res = first.bitxor(second.clone()).bitxor(third.clone());

    res
}

fn sigma_zero(x: FheUint32) -> FheUint32 {
    let mut first = rotate_right(x.clone(),7);

    let mut second = rotate_right(x.clone(),18);
    let mut third = x >> 3u32;

    let res = first.bitxor(second.clone()).bitxor(third.clone());

    res
}

fn sigma_one(x: FheUint32) -> FheUint32 {
    let mut first = rotate_right(x.clone(),17);

    let mut second = rotate_right(x.clone(),19);
    let mut third = x >> 10u32;

    let res = first.bitxor(second.clone()).bitxor(third.clone());

    res
}


// RotR(X, 2) ⊕ RotR(X, 13) ⊕ RotR(X, 22),

fn rotate_left(x: FheUint32, amount: u32) -> FheUint32 {
    let res  = (x.clone() << amount) | (x.clone() >> (32u32 - amount));
    res
}

fn rotate_right(x: FheUint32, amount: u32) -> FheUint32 {
    let res  = (x.clone() >> amount) | (x.clone() << (32u32 - amount));
    res
}
