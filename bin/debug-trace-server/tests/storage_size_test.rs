//! Storage size measurement test for debug-trace-server.
//!
//! Measures the on-disk storage cost of full blocks and LightWitnesses
//! for ~3000 tx blocks as stored in the redb database.
//!
//! # Running
//!
//! ```bash
//! cargo test -p debug-trace-server --test storage_size_test -- --include-ignored --nocapture
//! ```

use std::path::Path;

use validator_core::ValidatorDB;

const DATA_DIR: &str = "/home/krabat/.chain-ops/devnet/debug-trace-server";

#[test]
#[ignore]
fn test_measure_block_storage_sizes() {
    let db_path = Path::new(DATA_DIR).join("validator.redb");
    if !db_path.exists() {
        eprintln!("Database file not found: {}", db_path.display());
        return;
    }

    let db = ValidatorDB::new(&db_path).expect("Failed to open database");

    let records = db.get_recent_block_records(20).expect("Failed to get block records");

    if records.is_empty() {
        eprintln!("No blocks in database");
        return;
    }

    println!("\n{:-<90}", "");
    println!(
        "{:<10} {:<8} {:>14} {:>14} {:>14}",
        "Block#", "Txs", "Block(KB)", "Witness(KB)", "Total(KB)"
    );
    println!("{:-<90}", "");

    let mut total_block = 0usize;
    let mut total_witness = 0usize;
    let mut count = 0usize;

    for (number, hash) in &records {
        let (block_size, witness_size) =
            db.get_block_storage_sizes(*hash).expect("Failed to get storage sizes");

        if block_size == 0 && witness_size == 0 {
            continue;
        }

        // Decode block just to get tx count
        let (block, _witness) = db.get_block_and_witness(*hash).expect("Failed to get block");
        let tx_count = block.transactions.len();

        println!(
            "{:<10} {:<8} {:>11.1} {:>11.1} {:>11.1}",
            number,
            tx_count,
            block_size as f64 / 1024.0,
            witness_size as f64 / 1024.0,
            (block_size + witness_size) as f64 / 1024.0,
        );

        total_block += block_size;
        total_witness += witness_size;
        count += 1;
    }

    println!("{:-<90}", "");

    if count > 0 {
        let avg_block = total_block as f64 / count as f64;
        let avg_witness = total_witness as f64 / count as f64;
        println!(
            "{:<10} {:<8} {:>11.1} {:>11.1} {:>11.1}",
            "Average",
            "",
            avg_block / 1024.0,
            avg_witness / 1024.0,
            (avg_block + avg_witness) / 1024.0,
        );
        println!(
            "{:<10} {:<8} {:>11.1} {:>11.1} {:>11.1}",
            "Total",
            "",
            total_block as f64 / 1024.0,
            total_witness as f64 / 1024.0,
            (total_block + total_witness) as f64 / 1024.0,
        );

        println!("\n{} blocks measured", count);
        println!(
            "Average per block: {:.1} KB block + {:.1} KB witness = {:.1} KB total",
            avg_block / 1024.0,
            avg_witness / 1024.0,
            (avg_block + avg_witness) / 1024.0,
        );
        println!(
            "Projected 1000-block storage: {:.1} MB",
            (avg_block + avg_witness) * 1000.0 / 1024.0 / 1024.0,
        );
    }

    println!();
}
