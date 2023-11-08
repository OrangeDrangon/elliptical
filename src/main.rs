use core::panic;

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
    KeyPair,
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

fn generate_key_pair() -> anyhow::Result<()> {
    let curve = EllipticalCurve::secp256k1();

    let private_key = curve.gen_private_key();

    let uncompressed_public_key = match curve.nth_point(&private_key) {
        EllipticalPoint::Value(p) => p,
        EllipticalPoint::Identity => panic!("The identity is not useful"),
    };

    println!("private key {:?}", hex::encode(private_key.to_bytes_be()));
    println!(
        "public key {:?}",
        hex::encode(uncompressed_public_key.compress().to_bytes())
    );

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

fn encrypt(my_private_key: &str, their_public_key: &str, plaintext: &str) -> anyhow::Result<()> {
    let shared_secret = shared_secret(my_private_key, their_public_key)?;

    if plaintext.bytes().len() > 64 {
        panic!("can not encode message longer than 64 bytes");
    }

    let mut message_bytes = plaintext.as_bytes().to_vec();
    while message_bytes.len() < 64 {
        message_bytes.push(rand::thread_rng().gen_range(97..123));
    }

    let ciphertext = shared_secret
        .iter()
        .zip(message_bytes)
        .map(|(a, b)| a ^ b)
        .collect::<Box<_>>();

    println!("cipher text {}", hex::encode(ciphertext));

    Ok(())
}

fn decrypt(my_private_key: &str, their_public_key: &str, ciphertext: &str) -> anyhow::Result<()> {
    let shared_secret = shared_secret(my_private_key, their_public_key)?;
    let ciphertext_bytes = hex::decode(ciphertext)?;

    if ciphertext_bytes.len() < 64 {
        panic!("message must be 64 bytes");
    }

    let plaintext = shared_secret
        .iter()
        .zip(ciphertext_bytes)
        .map(|(a, b)| (a ^ b) as char)
        .collect::<String>();

    println!("plaintext {}", plaintext);

    Ok(())
}

pub fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::KeyPair => generate_key_pair(),
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
