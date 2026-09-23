use std::sync::RwLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    recovery_time: Duration,
    consecutive_failures: AtomicU32,
    last_failure_time: RwLock<Option<Instant>>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, recovery_time: Duration) -> Self {
        Self {
            failure_threshold,
            recovery_time,
            consecutive_failures: AtomicU32::new(0),
            last_failure_time: RwLock::new(None),
        }
    }

    pub fn is_allowed(&self) -> bool {
        let failures = self.consecutive_failures.load(Ordering::Relaxed);
        if failures < self.failure_threshold {
            return true;
        }

        if let Ok(guard) = self.last_failure_time.read()
            && let Some(last_fail) = *guard
            && last_fail.elapsed() >= self.recovery_time
        {
            return true;
        }
        false
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.last_failure_time.write() {
            *guard = Some(Instant::now());
        }
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }
}
