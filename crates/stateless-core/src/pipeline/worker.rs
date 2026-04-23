//! Worker stage: processor pool that consumes fetched blocks and emits results.

use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::debug;

use crate::pipeline::{config::WorkerResult, traits::BlockProcessor};

/// Spawns N worker tasks: `fetch_rx` → `processor.process()` → `result_tx`.
pub(crate) fn spawn_workers<P: BlockProcessor>(
    processor: Arc<P>,
    fetch_rx: kanal::Receiver<P::Input>,
    result_tx: kanal::Sender<WorkerResult<P::Output>>,
    count: usize,
) -> Vec<JoinHandle<()>> {
    (0..count)
        .map(|worker_id| {
            let processor = processor.clone();
            let fetch_rx = fetch_rx.clone();
            let result_tx = result_tx.clone();
            tokio::spawn(async move {
                let fetch_rx = fetch_rx.to_async();
                let result_tx = result_tx.to_async();
                loop {
                    let input = match fetch_rx.recv().await {
                        Ok(input) => input,
                        Err(_) => {
                            debug!(worker_id, "Fetch channel closed, stopping");
                            return;
                        }
                    };

                    let result = match processor.process(input).await {
                        Ok(output) => {
                            processor.on_task_done(worker_id, true);
                            Ok(output)
                        }
                        Err(e) => {
                            processor.on_task_done(worker_id, false);
                            let action = processor.error_action(&e);
                            // Erase to `Arc<dyn Error + ..>` so the advancer can log the
                            // source chain via `%err` without knowing the concrete type,
                            // and without paying a `String` allocation per failure.
                            Err((Arc::new(e) as Arc<dyn std::error::Error + Send + Sync>, action))
                        }
                    };

                    if result_tx.send(result).await.is_err() {
                        debug!(worker_id, "Result channel closed, stopping");
                        return;
                    }
                }
            })
        })
        .collect()
}
