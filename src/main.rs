use core::panic;
use std::iter::FromIterator;

use anyhow::Ok;
use clap::{Parser, Subcommand};
use num::BigUint;
use oblong::{
    curve::curve::EllipticalCurve,
    curve::point::{EllipticalCompressedPointValue, EllipticalPoint},
    sha::sha_512,
};
use rand::Rng;

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    KeyPair {
        #[arg(short, long, default_value_t = 1)]
        count: usize,
    },
    Encrypt {
        my_private_key: String,
        their_public_key: String,
        plaintext: String,
    },
    Decrypt {
        my_private_key: String,
        their_public_key: String,
        ciphertext: String,
    },
}

fn generate_key_pair(count: usize) -> anyhow::Result<()> {
    let curve = EllipticalCurve::secp256k1();

    let mut privates = vec![];
    let mut publics = vec![];

    for _ in 0..count {
        let private_key = curve.gen_private_key();
        privates.push(hex::encode(private_key.to_bytes_be()));

        let uncompressed_public_key = match curve.nth_point(&private_key) {
            EllipticalPoint::Value(p) => p,
            EllipticalPoint::Identity => panic!("The identity is not useful"),
        };

        publics.push(hex::encode(uncompressed_public_key.compress().to_bytes()));
    }

    println!("private {:?}", privates);
    println!("public {:?}", publics);
    Ok(())
}

fn shared_secret(my_private_key: &str, their_public_key: &str) -> anyhow::Result<Box<[u8]>> {
    let curve = EllipticalCurve::secp256k1();

    let my_private_key = hex::decode(my_private_key)?;
    let their_public_key = hex::decode(their_public_key)?;

    let my_private_key = BigUint::from_bytes_be(&my_private_key);
    let their_public_key = EllipticalCompressedPointValue::from_bytes(&their_public_key);
    let their_public_key = curve.uncompress(&their_public_key);

    let shared_point = match curve.multiply_unsigned(&their_public_key, &my_private_key) {
        EllipticalPoint::Value(p) => p,
        EllipticalPoint::Identity => panic!("The identity is not useful"),
    };

    let shared_point_bytes = shared_point.compress().to_bytes();

    Ok(sha_512(&shared_point_bytes))
}

const PREFIX: &[u8] = b"prefix's are fun";

fn encrypt(my_private_key: &str, their_public_key: &str, plaintext: &str) -> anyhow::Result<()> {
    let shared_secret = shared_secret(my_private_key, their_public_key)?;

    let mut message_bytes = plaintext.as_bytes().to_vec();
    while message_bytes.len() % 64 != 0 {
        message_bytes.push(rand::thread_rng().gen_range(97..123))
    }

    let mut key_stream = shared_secret;
    let mut cipher_text: Vec<u8> = vec![];
    for chunk in message_bytes.chunks_exact(64) {
        let mut prefix = PREFIX.to_vec();
        prefix.extend(key_stream.iter());
        key_stream = sha_512(&prefix);

        let c = key_stream
            .iter()
            .zip(chunk)
            .map(|(a, b)| a ^ b)
            .collect::<Box<_>>();

        cipher_text.extend(c.into_iter());
    }

    println!("cipher text: {}", hex::encode(cipher_text));

    Ok(())
}

fn decrypt(my_private_key: &str, their_public_key: &str, ciphertext: &str) -> anyhow::Result<()> {
    let shared_secret = shared_secret(my_private_key, their_public_key)?;
    let ciphertext_bytes = hex::decode(ciphertext)?;

    if ciphertext_bytes.len() % 64 != 0 {
        panic!("message must be multiple of 64 bytes");
    }

    let mut key_stream = shared_secret;
    let mut plain_text: Vec<char> = vec![];
    for chunk in ciphertext_bytes.chunks_exact(64) {
        let mut prefix = PREFIX.to_vec();
        prefix.extend(key_stream.iter());
        key_stream = sha_512(&prefix);

        let c = key_stream
            .iter()
            .zip(chunk)
            .map(|(a, b)| (a ^ b) as char)
            .collect::<Box<_>>();

        plain_text.extend(c.into_iter());
    }

    println!("plain text: {}", String::from_iter(plain_text));

    Ok(())
}

pub fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::KeyPair { count } => generate_key_pair(count),
        Command::Encrypt {
            my_private_key,
            their_public_key,
            plaintext,
        } => encrypt(&my_private_key, &their_public_key, &plaintext),
        Command::Decrypt {
            my_private_key,
            their_public_key,
            ciphertext,
        } => decrypt(&my_private_key, &their_public_key, &ciphertext),
    }
}
