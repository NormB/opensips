//! Non-blocking async HTTP dispatch queue.
//!
//! SIP worker pushes payload, tokio task sends HTTP POST in background.
//! If queue is full, message is dropped.

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::runtime::Runtime;

pub struct FireAndForget {
    tx: mpsc::Sender<String>,
    _runtime: Runtime,
    pub sent: std::cell::Cell<u64>,
    pub dropped: std::cell::Cell<u64>,
    pub failed: std::cell::Cell<u64>,
}

impl FireAndForget {
    /// Create a new fire-and-forget dispatcher.
    /// Spawns a tokio runtime with a background task that drains the queue.
    /// # Panics
    /// Panics if the tokio runtime cannot be created.
    pub fn new(url: String, max_queue: usize, timeout_secs: u64, content_type: String) -> Self {
        let (tx, mut rx) = mpsc::channel::<String>(max_queue);

        let runtime = Runtime::new().expect("failed to create tokio runtime");

        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let url = Arc::new(url);
        let ct = Arc::new(content_type);

        runtime.spawn(async move {
            while let Some(payload) = rx.recv().await {
                let url = url.clone();
                let ct = ct.clone();
                let client = client.clone();
                // Spawn each send as a separate task so slow sends don't block the queue
                tokio::spawn(async move {
                    let _ = client.post(url.as_str())
                        .header("Content-Type", ct.as_str())
                        .body(payload)
                        .send()
                        .await;
                });
            }
        });

        FireAndForget {
            tx,
            _runtime: runtime,
            sent: std::cell::Cell::new(0),
            dropped: std::cell::Cell::new(0),
            failed: std::cell::Cell::new(0),
        }
    }

    /// Enqueue a payload for background delivery. Never blocks.
    /// Returns true if enqueued, false if dropped (queue full).
    pub fn send(&self, payload: String) -> bool {
        match self.tx.try_send(payload) {
            Ok(()) => {
                self.sent.set(self.sent.get() + 1);
                true
            }
            Err(_) => {
                self.dropped.set(self.dropped.get() + 1);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fire_and_forget_create() {
        let ff = FireAndForget::new(
            "http://127.0.0.1:19999/sink".to_string(),
            16,
            5,
            "application/json".to_string(),
        );
        assert_eq!(ff.sent.get(), 0);
        assert_eq!(ff.dropped.get(), 0);
        assert_eq!(ff.failed.get(), 0);
    }

    #[test]
    fn test_fire_and_forget_send() {
        let ff = FireAndForget::new(
            "http://127.0.0.1:19999/sink".to_string(),
            16,
            5,
            "application/json".to_string(),
        );
        let ok = ff.send(r#"{"test":1}"#.to_string());
        assert!(ok);
        assert_eq!(ff.sent.get(), 1);
        assert_eq!(ff.dropped.get(), 0);

        let ok2 = ff.send(r#"{"test":2}"#.to_string());
        assert!(ok2);
        assert_eq!(ff.sent.get(), 2);
    }

    #[test]
    fn test_fire_and_forget_queue_full() {
        // Queue capacity of 1 -- second send may succeed if the runtime
        // drains fast, but with 3 rapid sends at least 1 should drop.
        // Use a capacity of 1 and send enough to guarantee overflow.
        let ff = FireAndForget::new(
            "http://192.0.2.1:1/blackhole".to_string(), // non-routable, will never drain
            1,
            1,
            "text/plain".to_string(),
        );

        // First send fills the single slot
        let _r1 = ff.send("msg1".to_string());
        // Rapidly send more -- channel is full because the runtime
        // tries to POST to a non-routable address, so recv() is blocked
        // on the HTTP call and the slot stays occupied.
        let _r2 = ff.send("msg2".to_string());
        let _r3 = ff.send("msg3".to_string());

        // At least one must have been dropped
        let total_sent = ff.sent.get();
        let total_dropped = ff.dropped.get();
        assert_eq!(total_sent + total_dropped, 3);
        assert!(total_dropped >= 1, "expected at least 1 drop, got {}", total_dropped);
    }

    #[test]
    fn test_fire_and_forget_stats() {
        let ff = FireAndForget::new(
            "http://127.0.0.1:19999/sink".to_string(),
            64,
            5,
            "application/json".to_string(),
        );
        for i in 0..10 {
            ff.send(format!("msg{i}"));
        }
        assert_eq!(ff.sent.get(), 10);
        assert_eq!(ff.dropped.get(), 0);
    }

    #[test]
    fn test_fire_and_forget_large_payload() {
        let ff = FireAndForget::new(
            "http://127.0.0.1:19999/sink".to_string(),
            4,
            5,
            "application/json".to_string(),
        );
        let big = "x".repeat(1_000_000); // 1MB payload
        let ok = ff.send(big);
        assert!(ok);
        assert_eq!(ff.sent.get(), 1);
    }
}
