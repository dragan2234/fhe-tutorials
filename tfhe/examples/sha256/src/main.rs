use std::ops::{BitAnd, ShlAssign, Shl, BitOr, Neg};

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

    let input_ciphertext = InputCiphertext::encrypt(padded_input, &client_key);

    let h_ciphertext = InputCiphertext::encrypt(hehe, &client_key);

    let k_ciphertext = InputCiphertext::encrypt(keke, &client_key);

    let decrypted_result: u32 = input_ciphertext.inner.first().unwrap().decrypt(&client_key);


    let mut v = input_ciphertext.inner.first().unwrap();

    let mut e = k_ciphertext.inner.first().unwrap();

    // # In n<<d, last d bits are 0.
    // # To put first 3 bits of n at
    // # last, do bitwise or of n<<d
    // # with n >>(INT_BITS - d)
    // return (n << d)|(n >> (INT_BITS - d))
    // (v as FheUint32) <<= 2;

    // &v.bitshift
    // &v << 2;


    let bitwised = (v << 2u32) | (v >> 30u32);


    let decrypted_bitwised: u32 = bitwised.decrypt(&client_key);

    assert_eq!(decrypted_bitwised, 1234538761);

    assert_eq!(decrypted_result, 1382376514);

    let decrypted_result_h: u32 = h_ciphertext.inner.first().unwrap().decrypt(&client_key);

    assert_eq!(1779033703, decrypted_result_h);

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
// pub struct Sha256 {
//     state: [u32; 8],
//     completed_data_blocks: u64,
//     pending: [u8; 64],
//     num_pending: usize,
// }

// impl Default for Sha256 {
//     fn default() -> Self {
//         Self {
//             state: H,
//             completed_data_blocks: 0,
//             pending: [0u8; 64],
//             num_pending: 0,
//         }
//     }
// }
// impl Sha256 {
//     pub fn with_state(state: [u32; 8]) -> Self {
//         Self {
//             state,
//             completed_data_blocks: 0,
//             pending: [0u8; 64],
//             num_pending: 0,
//         }
//     }
// }

// fn mainewq() {
//     let config = ConfigBuilder::all_disabled()
//     .enable_default_uint16()
//     .build();

//     let (client_key, server_key) = generate_keys(config);
//      // Generate the client key and the server key:
//      let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);

//     let bytes = "helo".as_bytes();
//     let u32_number = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
//     let test = 123 as u16;
//     let another_test = 1234 as u32;

//     let a = FheUint32::encrypt(another_test, &client_key);

//     let b = FheUint16::encrypt(test, &client_key);

//     let mut ct_input_string = cks.encrypt(u32_number);

//      let msg1 = 14;
//      let msg2 = 97;
    
//      let mut ct1 = cks.encrypt(msg1);
//      let mut ct2 = cks.encrypt(msg2);
    
//      let ct_res = sks.smart_bitxor(&mut ct1, &mut ct2);
//      // Decrypt:
//      let dec_result: u64 = cks.decrypt(&ct_res);
//      assert_eq!(dec_result, msg1 ^ msg2);

//     println!("test");
// }
// fn main() {
//     let mut num = Number32 {
//         chunks: vec![0b1101, 0b0010, 0b1001, 0b0100],
//     };

//     println!("Before rotation:");
//     num.print_chunks();

//     num.rotate_left(6);

//     println!("After rotation:");
//     num.print_chunks();
// }

// fn mains() {
//     // We generate a set of client/server keys, using the default parameters:
//     let (client_key, server_key) = gen_keys(PARAM_MESSAGE_4_CARRY_4);

//     let s = "hello world";
//     let mut bit_vec = Vec::new();

//     let mut ct_vec = Vec::new();

//     // process string as bytes and push them as 4bit values into bit_vec
//     for b in s.as_bytes() {
//         bit_vec.push((b & 0b11110000) >> 4);
//         bit_vec.push(b & 0b00001111);
//     }

//     println!("bit_vec: {:?}", bit_vec);
//     for value in &bit_vec {
//         println!("{:04b}", value);
//     }
//     println!("{}", bit_vec.len());

//     // push the encrypted 4bit values into ct_vec 
//     for b in bit_vec {
//         ct_vec.push(client_key.encrypt(b.into()));
//     }



//     // @todo: process string as bytes
//     // process bytes as shortint
//     // encrypt the input as vector of bits (4 bits? 8 bits?)
//     // do the sha256 over encrypted values using shortint library
//     // operations: And, Xor, Or, Rot, Shr, Add (mod 2^32)
//     // decrypt and compare with standard sha256 rust

//     // test code with some examples how tfhe-rs work:\
//     // let msg1 = 3;
//     // let msg2 = 3;
//     // let scalar = 4;

//     // let modulus = client_key.parameters.message_modulus.0;

//     // // We use the client key to encrypt two messages:
//     // let mut ct_1 = client_key.encrypt(msg1);
//     // let ct_2 = client_key.encrypt(msg2);

//     // server_key.unchecked_scalar_mul_assign(&mut ct_1, scalar);
//     // server_key.unchecked_sub_assign(&mut ct_1, &ct_2);
//     // server_key.unchecked_mul_lsb_assign(&mut ct_1, &ct_2);

//     // // We use the client key to decrypt the output of the circuit:
//     // let output = client_key.decrypt(&ct_1);
//     // println!("expected {}, found {}", ((msg1 * scalar as u64 - msg2) * msg2) % modulus as u64, output);
// }


fn ch_function(x: FheUint32, y: FheUint32, z: FheUint32) -> FheUint32 {
    let res = x.clone().bitand(y).bitor(x.clone().neg().bitand(z));
    res 
}

fn maj_function(x: FheUint32, y: FheUint32, z: FheUint32) -> FheUint32 {
    let res = x.clone().bitand(y.clone()).bitor(x.clone().bitand(z.clone())).bitor(y.clone().bitand(z.clone()));
    res
}

fn capsigma_function(x: FheUint32) -> FheUint32 {
    let mut first = rotate_right(x.clone(),2);

    let mut second = rotate_right(x.clone(),13);
    let mut third = rotate_right(x.clone(),22);

    let res = first.bitand(second.clone()).bitand(third.clone());

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