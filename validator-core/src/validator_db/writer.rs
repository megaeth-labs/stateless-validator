//! Background writer for asynchronous persistence
//!
//! This module provides a channel-based system for persisting data from
//! the in-memory storage to redb asynchronously, without blocking validation.

use std::path::Path;

use alloy_primitives::{B256, BlockHash, BlockNumber};
use alloy_rpc_types_eth::Block;
use op_alloy_rpc_types::Transaction;
use revm::state::Bytecode;
use salt::SaltWitness;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::{validator_db::ValidatorDB, withdrawals::MptWitness};

/// Messages sent to the background writer
pub enum WriteMsg {
    /// Store validation data (block, witnesses)
    ValidationData(Vec<(Block<Transaction>, SaltWitness, MptWitness)>),
    /// Store contract bytecodes
    ContractCodes(Vec<Bytecode>),
    /// Store canonical chain entry
    CanonicalChainEntry(Vec<(BlockNumber, BlockHash, B256, B256)>),
    /// Prune history
    PruneHistory(BlockNumber),
}

/// Handle for sending data to the background writer
#[derive(Clone)]
pub struct WriterHandle {
    sender: mpsc::Sender<WriteMsg>,
}

impl WriterHandle {
    /// Send a message to the writer.
    /// Returns immediately - does not block. Drops message if channel is full.
    pub fn send(&self, msg: WriteMsg) {
        // Use try_send to avoid blocking - drop if channel full
        if self.sender.try_send(msg).is_err() {
            // Channel full or closed - this is acceptable per requirements
            debug!("[Writer] Channel full, dropping data");
        }
    }

    /// Send validation data (block + witnesses) for persistence
    pub fn store_validation_data(&self, data: Vec<(Block<Transaction>, SaltWitness, MptWitness)>) {
        self.send(WriteMsg::ValidationData(data));
    }

    /// Send contract codes for persistence
    pub fn store_contract_codes(&self, bytecodes: Vec<Bytecode>) {
        if !bytecodes.is_empty() {
            self.send(WriteMsg::ContractCodes(bytecodes));
        }
    }

    /// Send canonical chain entry for persistence
    pub fn store_canonical_chain_entry(&self, entries: Vec<(BlockNumber, BlockHash, B256, B256)>) {
        self.send(WriteMsg::CanonicalChainEntry(entries));
    }

    /// Send prune request
    pub fn prune_history(&self, before_block: BlockNumber) {
        self.send(WriteMsg::PruneHistory(before_block));
    }
}

/// Background writer that persists data to redb
pub struct Writer {
    db: ValidatorDB,
    receiver: mpsc::Receiver<WriteMsg>,
}

impl Writer {
    /// Create a new writer with the given database path
    ///
    /// Returns a handle for sending data and spawns the background writer task.
    /// The channel has a bounded capacity to prevent unbounded memory growth.
    pub fn new(
        db_path: impl AsRef<Path>,
    ) -> Result<(WriterHandle, Self), crate::validator_db::ValidationDbError> {
        // Bounded channel - drops messages if writer falls behind
        let (sender, receiver) = mpsc::channel(1000);
        let db = ValidatorDB::new(db_path)?;

        let handle = WriterHandle { sender };
        let writer = Self { db, receiver };

        Ok((handle, writer))
    }

    /// Run the writer loop
    ///
    /// Processes messages from the channel and writes to the database.
    /// Should be spawned as a background task.
    pub async fn run(mut self) {
        use std::sync::Arc;

        info!("[Writer] Background writer started");

        // Wrap db in Arc for sharing with spawn_blocking tasks
        let db = Arc::new(self.db);

        while let Some(msg) = self.receiver.recv().await {
            match msg {
                WriteMsg::PruneHistory(before_block) => {
                    // Spawn pruning in background thread to avoid blocking the writer loop
                    let db_clone = Arc::clone(&db);
                    tokio::task::spawn_blocking(move || {
                        debug!("[Writer] Pruning history before block {}", before_block);
                        match db_clone.prune_history(before_block) {
                            Ok(pruned) if pruned > 0 => {
                                info!("[Writer] Pruned {} blocks from debug database", pruned);
                            }
                            Ok(_) => {}
                            Err(e) => {
                                error!("[Writer] Failed to prune history: {e}");
                            }
                        }
                    });
                }
                other => {
                    if let Err(e) = Self::handle_message(&db, other) {
                        error!("[Writer] Failed to write debug data: {e}");
                    }
                }
            }
        }

        info!("[Writer] Background writer shutting down");
    }

    fn handle_message(
        db: &ValidatorDB,
        msg: WriteMsg,
    ) -> Result<(), crate::validator_db::ValidationDbError> {
        match msg {
            WriteMsg::ValidationData(data) => {
                debug!("[Writer] Storing validation data for {} blocks", data.len());
                db.store_validation_data(data)?;
            }
            WriteMsg::ContractCodes(bytecodes) => {
                debug!("[Writer] Storing {} contract codes", bytecodes.len());
                db.store_contract_codes(bytecodes)?;
            }
            WriteMsg::CanonicalChainEntry(entries) => {
                debug!(
                    "[Writer] Storing canonical chain entry for block {:?}",
                    entries.iter().map(|i| i.0).collect::<Vec<_>>()
                );
                db.store_canonical_entries(entries)?;
            }
            WriteMsg::PruneHistory(_) => {
                // Handled in run() with spawn_blocking
                unreachable!()
            }
        }
        Ok(())
    }

    /// Get a reference to the underlying database (for reading genesis, etc.)
    pub fn db(&self) -> &ValidatorDB {
        &self.db
    }
}
