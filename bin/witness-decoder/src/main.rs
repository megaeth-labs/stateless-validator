use alloy_primitives::{B256, BlockNumber};
use clap::Parser;
use eyre::{Result, anyhow};
use serde::Serialize;
use std::{fs::File, io::Read, path::PathBuf};
use validator_core::{
    SaltWitnessState, WitnessStatus,
    storage::{BlockFileManager, deserialized_state_data},
};

#[derive(Parser, Debug)]
#[clap(author, version, about = "Decode .w witness files from the stateless validator", long_about = None)]
struct Args {
    /// Path to the .w witness file to decode
    #[clap(short, long)]
    file: PathBuf,

    /// Output format: pretty (default), json, or raw
    #[clap(long, default_value = "pretty")]
    format: String,

    /// Verify the BLAKE3 hash integrity
    #[clap(long, default_value = "true")]
    verify_hash: bool,

    /// Show hex dump of witness data (first N bytes)
    #[clap(long, default_value = "0")]
    hex_dump_bytes: usize,
}

#[derive(Serialize, Debug)]
struct WitnessInfo {
    file_name: String,
    block_number: BlockNumber,
    block_hash: String,
    status: String,
    pre_state_root: String,
    parent_hash: String,
    lock_time: u64,
    blob_count: usize,
    blob_ids: Vec<String>,
    witness_data_size: usize,
    witness_data_hex: Option<String>,
    hash_verified: bool,
}

fn format_state(state: &SaltWitnessState) -> String {
    match state {
        SaltWitnessState::Idle => "Idle".to_string(),
        SaltWitnessState::Processing => "Processing".to_string(),
        SaltWitnessState::Witnessed => "Witnessed".to_string(),
        SaltWitnessState::Verifying => "Verifying".to_string(),
        SaltWitnessState::UploadingStep1 => "UploadingStep1".to_string(),
        SaltWitnessState::UploadingStep2 => "UploadingStep2".to_string(),
        SaltWitnessState::Completed => "Completed".to_string(),
    }
}

fn format_hash(hash: &B256) -> String {
    format!("0x{}", hex::encode(hash.as_slice()))
}

fn decode_witness_file(
    file_path: &PathBuf,
    verify_hash: bool,
    hex_dump_bytes: usize,
) -> Result<WitnessInfo> {
    let mut file = File::open(file_path)
        .map_err(|e| anyhow!("Failed to open file {}: {}", file_path.display(), e))?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|e| anyhow!("Failed to read file {}: {}", file_path.display(), e))?;

    // Deserialize the outer StateData structure
    let state_data = deserialized_state_data(contents)
        .map_err(|e| anyhow!("Failed to deserialize state data: {}", e))?;

    // Verify hash if requested
    let hash_verified = if verify_hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&state_data.data);
        let computed_hash = B256::from_slice(hasher.finalize().as_bytes());
        computed_hash == state_data.hash
    } else {
        true // Skip verification
    };

    // Deserialize the inner WitnessStatus structure
    let (witness_status, _): (WitnessStatus, usize) =
        bincode::serde::decode_from_slice(&state_data.data, bincode::config::legacy())
            .map_err(|e| anyhow!("Failed to deserialize witness status: {}", e))?;

    // Extract file name info
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let (file_block_number, file_block_hash) = BlockFileManager::parse_filename(&file_name);

    // Create hex dump if requested
    let witness_data_hex = if hex_dump_bytes > 0 {
        let bytes_to_show = std::cmp::min(hex_dump_bytes, witness_status.witness_data.len());
        Some(hex::encode(&witness_status.witness_data[..bytes_to_show]))
    } else {
        None
    };

    Ok(WitnessInfo {
        file_name,
        block_number: file_block_number,
        block_hash: format_hash(&file_block_hash),
        status: format_state(&witness_status.status),
        pre_state_root: format_hash(&witness_status.pre_state_root),
        parent_hash: format_hash(&witness_status.parent_hash),
        lock_time: witness_status.lock_time,
        blob_count: witness_status.blob_ids.len(),
        blob_ids: witness_status
            .blob_ids
            .iter()
            .map(|blob_id| format!("0x{}", hex::encode(blob_id)))
            .collect(),
        witness_data_size: witness_status.witness_data.len(),
        witness_data_hex,
        hash_verified,
    })
}

fn main() -> Result<()> {
    let args = Args::parse();

    let witness_info = decode_witness_file(&args.file, args.verify_hash, args.hex_dump_bytes)?;

    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&witness_info)?);
        }
        "raw" => {
            println!("{:#?}", witness_info);
        }
        _ => {
            println!("=== Witness File Information ===");
            println!("File: {}", witness_info.file_name);
            println!("Block Number: {}", witness_info.block_number);
            println!("Block Hash: {}", witness_info.block_hash);
            println!("Status: {}", witness_info.status);
            println!("Pre-State Root: {}", witness_info.pre_state_root);
            println!("Parent Hash: {}", witness_info.parent_hash);
            println!("Lock Time: {} (unix timestamp)", witness_info.lock_time);
            println!("Blob Count: {}", witness_info.blob_count);

            if !witness_info.blob_ids.is_empty() {
                println!("Blob IDs:");
                for (i, blob_id) in witness_info.blob_ids.iter().enumerate() {
                    println!("  [{}]: {}", i, blob_id);
                }
            }

            println!(
                "Witness Data Size: {} bytes",
                witness_info.witness_data_size
            );

            if let Some(hex_data) = &witness_info.witness_data_hex {
                println!("Witness Data (first {} bytes):", args.hex_dump_bytes);
                println!("  {}", hex_data);
            }

            println!("Hash Verified: {}", witness_info.hash_verified);

            if !witness_info.hash_verified {
                println!("⚠️  WARNING: Hash verification failed - file may be corrupted!");
            }
        }
    }

    Ok(())
}
