use mailent_domain::NormalizedObservation;
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;
use tracing::warn;

#[derive(Debug)]
pub struct SpoolStats {
    pub processed: u64,
    pub spooled: u64,
    pub dropped: u64,
}

#[derive(Clone)]
pub struct BoundedSpooler {
    core_endpoint: String,
    _spool_dir: PathBuf,
    capacity: usize,
    queue: Arc<Mutex<VecDeque<NormalizedObservation>>>,
    processed_count: Arc<AtomicU64>,
    dropped_count: Arc<AtomicU64>,
    client: reqwest::Client,
}

impl BoundedSpooler {
    pub fn new(core_endpoint: String, spool_dir: PathBuf, capacity: usize) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            core_endpoint,
            _spool_dir: spool_dir,
            capacity: capacity.max(10),
            queue: Arc::new(Mutex::new(VecDeque::new())),
            processed_count: Arc::new(AtomicU64::new(0)),
            dropped_count: Arc::new(AtomicU64::new(0)),
            client,
        }
    }

    pub fn stats(&self) -> SpoolStats {
        let processed = self.processed_count.load(Ordering::Relaxed);
        let dropped = self.dropped_count.load(Ordering::Relaxed);
        // We can approximate spooled count without blocking
        let spooled = {
            if let Ok(guard) = self.queue.try_lock() {
                guard.len() as u64
            } else {
                0
            }
        };
        SpoolStats {
            processed,
            spooled,
            dropped,
        }
    }

    pub async fn submit(&self, observation: NormalizedObservation) {
        self.processed_count.fetch_add(1, Ordering::Relaxed);

        // Try to send immediately if queue is empty
        let is_empty = {
            let guard = self.queue.lock().await;
            guard.is_empty()
        };

        if is_empty {
            match self.send_to_core(&observation).await {
                Ok(_) => {
                    return;
                }
                Err(err) => {
                    warn!(error = %err, "Core unreachable; spooling observation");
                }
            }
        }

        // Enqueue into bounded spool
        let mut guard = self.queue.lock().await;
        if guard.len() >= self.capacity {
            // Drop oldest observation
            guard.pop_front();
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
            warn!(
                capacity = self.capacity,
                "Spool capacity reached; dropped oldest observation to prevent OOM"
            );
        }
        guard.push_back(observation);
    }

    pub async fn drain_pending(&self) {
        loop {
            let next_item = {
                let guard = self.queue.lock().await;
                guard.front().cloned()
            };

            let Some(observation) = next_item else {
                break;
            };

            match self.send_to_core(&observation).await {
                Ok(_) => {
                    let mut guard = self.queue.lock().await;
                    guard.pop_front();
                }
                Err(err) => {
                    tracing::debug!(error = %err, "Drain attempt paused; Core still unreachable");
                    break;
                }
            }
        }
    }

    async fn send_to_core(&self, observation: &NormalizedObservation) -> Result<(), String> {
        let bytes = mailent_events::wire::encode(observation).map_err(|e| e.to_string())?;
        let url = format!(
            "{}/api/v1/observations",
            self.core_endpoint.trim_end_matches('/')
        );

        let res = self
            .client
            .post(&url)
            .header("Content-Type", "application/x-protobuf")
            .body(bytes)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let status = res.status();
        if !status.is_success() {
            let text = res.text().await.unwrap_or_default();
            return Err(format!("HTTP {status}: {text}"));
        }

        Ok(())
    }
}
