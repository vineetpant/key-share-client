use base64::{engine::general_purpose, Engine};
use clap::{Parser, Subcommand};
use key_share_service::{
    DecryptionRequest, DecryptionResponse, EncryptionRequest, EncryptionResponse, PublicKeyResponse,
};
use reqwest::Client;
use std::collections::HashMap;
use threshold_crypto::{Ciphertext, PublicKeySet};

#[derive(Parser)]
#[command(name = "threshold_client")]
#[command(about = "CLI for Threshold Encryption Service", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Retrieve the public key
    PublicKey {},
    /// Encrypt a plaintext message
    Encrypt {
        #[arg(short, long)]
        plaintext: String,
    },
    /// Decrypt a ciphertext
    Decrypt {
        #[arg(short, long)]
        ciphertext: String,
    },
}

async fn get_public_key(client: &Client, base_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pub_key_resp: PublicKeyResponse = client
        .get(format!("{}/public_key", base_url))
        .send()
        .await?
        .json()
        .await?;

    let pub_key_set: PublicKeySet = serde_json::from_str(&pub_key_resp.pub_key_set)?;

    // Print the public key in Base64 format
    let pub_key_set_bytes = bincode::serialize(&pub_key_set).unwrap();
    let pub_key_base64 = general_purpose::STANDARD.encode(pub_key_set_bytes);
    println!("Public Key (Base64): {}", pub_key_base64);
    Ok(())
}

async fn encrypt_message(
    client: &Client,
    base_url: &str,
    plaintext: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let encrypt_resp: EncryptionResponse = client
        .post(format!("{}/encrypt", base_url))
        .json(&EncryptionRequest { plaintext })
        .send()
        .await?
        .json()
        .await?;

    println!("Ciphertext: {}", encrypt_resp.ciphertext);
    Ok(())
}

async fn decrypt_message(
    client: &Client,
    base_url: &str,
    ciphertext: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let decrypt_resp: DecryptionResponse = client
        .post(format!("{}/decrypt", base_url))
        .json(&DecryptionRequest {
            ciphertext: ciphertext.clone(),
        })
        .send()
        .await?
        .json()
        .await?;

    // Combine the decryption shares to retrieve the plaintext
    let pub_key_resp: PublicKeyResponse = client
        .get(format!("{}/public_key", base_url))
        .send()
        .await?
        .json()
        .await?;

    let pub_key_set: PublicKeySet = serde_json::from_str(&pub_key_resp.pub_key_set)?;
    let ciphertext_bytes = general_purpose::STANDARD.decode(&ciphertext)?;
    let ciphertext_str = String::from_utf8(ciphertext_bytes)?;

    let ciphertext: Ciphertext = serde_json::from_str(&ciphertext_str)?;

    let mut shares = HashMap::new();
    for (i, share) in decrypt_resp.decryption_shares {
        shares.insert(i, share);
    }

    let plaintext_bytes = pub_key_set
        .decrypt(&shares, &ciphertext)
        .map_err(|_| "decryption failed")?;
    let plaintext_result = String::from_utf8(plaintext_bytes)?;

    println!("Decrypted Plaintext: {}", plaintext_result);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let client = Client::new();
    let base_url = "http://localhost:8000";

    match &cli.command {
        Commands::PublicKey {} => get_public_key(&client, base_url).await?,
        Commands::Encrypt { plaintext } => {
            encrypt_message(&client, base_url, plaintext.clone()).await?
        }
        Commands::Decrypt { ciphertext } => {
            decrypt_message(&client, base_url, ciphertext.clone()).await?
        }
    }

    Ok(())
}
