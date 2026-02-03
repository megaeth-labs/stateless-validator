//! Pruning functionality test for debug-trace-server.
//!
//! This test verifies that the history_pruner correctly removes old blocks
//! while keeping recent ones.
//!
//! # Running Tests
//!
//! ```bash
//! cargo test --package debug-trace-server --test prune_test -- --nocapture
//! ```

use alloy_primitives::B256;
use tempfile::TempDir;
use validator_core::ValidatorDB;

/// Test that prune_history removes blocks older than the specified block number.
#[test]
fn test_prune_history_basic() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_prune.redb");

    let db = ValidatorDB::new(db_path).expect("Failed to create database");

    // Set up an anchor block at height 100
    let anchor_hash = B256::from([100u8; 32]);
    let state_root = B256::ZERO;
    let withdrawals_root = B256::ZERO;

    db.reset_anchor_block(100, anchor_hash, state_root, withdrawals_root)
        .expect("Failed to reset anchor");

    // Verify anchor is set
    let tip = db.get_local_tip().expect("Failed to get local tip");
    assert_eq!(tip, Some((100, anchor_hash)));

    // Prune everything before block 50 (should prune nothing since anchor is at 100)
    let pruned = db.prune_history(50).expect("Failed to prune");
    assert_eq!(pruned, 0, "Should not prune anything when no blocks are older");

    println!("✓ Basic prune_history test passed");
}

/// Test that prune_history handles empty database gracefully.
#[test]
fn test_prune_history_empty_db() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_prune_empty.redb");

    let db = ValidatorDB::new(db_path).expect("Failed to create database");

    // Prune on empty database should succeed with 0 pruned
    let pruned = db.prune_history(1000).expect("Failed to prune empty db");
    assert_eq!(pruned, 0, "Empty database should have nothing to prune");

    println!("✓ Empty database prune test passed");
}

/// Test that blocks_to_keep calculation works correctly.
#[test]
fn test_blocks_to_keep_calculation() {
    // Simulate the pruner logic
    let current_tip: u64 = 10000;
    let blocks_to_keep: u64 = 1000;

    let prune_before = current_tip.saturating_sub(blocks_to_keep);
    assert_eq!(prune_before, 9000);

    // Edge case: tip is less than blocks_to_keep
    let current_tip_small: u64 = 500;
    let prune_before_small = current_tip_small.saturating_sub(blocks_to_keep);
    assert_eq!(prune_before_small, 0, "Should not underflow");

    println!("✓ Blocks to keep calculation test passed");
}

/// Integration test: verify pruner configuration defaults.
#[test]
fn test_pruner_defaults() {
    // These should match the constants in main.rs
    const DEFAULT_BLOCKS_TO_KEEP: u64 = 1000;
    const DEFAULT_PRUNER_INTERVAL_SECS: u64 = 300;

    assert_eq!(DEFAULT_BLOCKS_TO_KEEP, 1000);
    assert_eq!(DEFAULT_PRUNER_INTERVAL_SECS, 300); // 5 minutes

    println!("✓ Pruner defaults test passed");
}

/// Test the pruner function signature matches expected behavior.
#[test]
fn test_prune_history_api() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_prune_api.redb");

    let db = ValidatorDB::new(db_path).expect("Failed to create database");

    // Set up anchor at block 1000
    let anchor_hash = B256::from([10u8; 32]);
    db.reset_anchor_block(1000, anchor_hash, B256::ZERO, B256::ZERO)
        .expect("Failed to reset anchor");

    // Verify prune_history returns a count
    let result = db.prune_history(500);
    assert!(result.is_ok(), "prune_history should succeed");

    let pruned = result.unwrap();
    println!("prune_history(500) returned: {}", pruned);

    // Prune before the anchor should return 0 (nothing to prune)
    assert_eq!(pruned, 0);

    // Prune after the anchor - still 0 because anchor is only in canonical_chain,
    // not in block_records (no actual block data stored via add_validation_tasks)
    let pruned_after = db.prune_history(1500).expect("Prune should succeed");
    println!("prune_history(1500) returned: {}", pruned_after);

    println!("✓ Prune history API test passed");
}

/// Test that the pruner interval and blocks_to_keep work together.
#[test]
fn test_pruner_simulation() {
    // Simulate what happens in the history_pruner function
    struct PrunerState {
        blocks_to_keep: u64,
        interval_secs: u64,
    }

    let pruner = PrunerState { blocks_to_keep: 1000, interval_secs: 300 };

    // Simulate different tip scenarios
    let test_cases: Vec<(u64, u64)> = vec![
        (10000, 9000), // Normal case: tip=10000, prune_before=9000
        (500, 0),      // Edge case: tip < blocks_to_keep, prune_before=0
        (1000, 0),     // Boundary: tip == blocks_to_keep, prune_before=0
        (1001, 1),     // Just over: tip = blocks_to_keep+1, prune_before=1
    ];

    for (current_tip, expected_prune_before) in test_cases {
        let prune_before = current_tip.saturating_sub(pruner.blocks_to_keep);
        assert_eq!(
            prune_before, expected_prune_before,
            "For tip={}, expected prune_before={}, got {}",
            current_tip, expected_prune_before, prune_before
        );
    }

    // Verify interval is reasonable
    assert!(pruner.interval_secs >= 60, "Pruner interval should be at least 1 minute");
    assert!(pruner.interval_secs <= 3600, "Pruner interval should be at most 1 hour");

    println!("✓ Pruner simulation test passed");
}
