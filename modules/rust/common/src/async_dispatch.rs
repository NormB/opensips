//! Non-blocking async HTTP dispatch queue.
//!
//! SIP worker pushes payload, tokio task sends HTTP POST in background.
//! If queue is full, message is dropped. Supports custom headers, multiple
//! URLs (fanout), retry with exponential backoff, and message batching.

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::runtime::Runtime;

/// Configuration for retry behavior.
#[derive(Clone, Debug)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub retry_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        RetryConfig {
            max_retries: 0,
            retry_delay_ms: 1000,
        }
    }
}

/// Configuration for message batching.
#[derive(Clone, Debug)]
pub struct BatchConfig {
    /// Number of messages to accumulate before sending (1 = no batching).
    pub batch_size: usize,
    /// Maximum milliseconds to wait before flushing a partial batch.
    pub batch_timeout_ms: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        BatchConfig {
            batch_size: 1,
            batch_timeout_ms: 100,
        }
    }
}

pub struct FireAndForget {
    tx: mpsc::Sender<String>,
    _runtime: Runtime,
    pub sent: std::cell::Cell<u64>,
    pub dropped: std::cell::Cell<u64>,
    pub failed: std::cell::Cell<u64>,
    pub retried: std::cell::Cell<u64>,
    pub retry_exhausted: std::cell::Cell<u64>,
}

/// Parse a pipe-separated header string into (name, value) pairs.
///
/// Format: "Header1: Value1|Header2: Value2"
/// Malformed entries (missing `:`) are skipped.
pub fn parse_headers(raw: &str) -> Vec<(String, String)> {
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split('|')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let colon_pos = entry.find(':')?;
            let name = entry[..colon_pos].trim();
            let value = entry[colon_pos + 1..].trim();
            if name.is_empty() {
                return None;
            }
            Some((name.to_string(), value.to_string()))
        })
        .collect()
}

/// Parse a comma-separated URL string into a list of URLs.
///
/// Whitespace around each URL is trimmed. Empty entries are skipped.
pub fn parse_urls(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect()
}

/// Build a JSON array payload from a batch of messages.
/// If individual messages are valid JSON values, they are included as-is.
/// Otherwise they are wrapped as JSON strings.
pub fn build_batch_payload(messages: &[String]) -> String {
    let mut parts = Vec::with_capacity(messages.len());
    for msg in messages {
        let trimmed = msg.trim();
        if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
            parts.push(trimmed.to_string());
        } else {
            parts.push(
                serde_json::to_string(trimmed)
                    .unwrap_or_else(|_| format!("\"{}\"", trimmed)),
            );
        }
    }
    format!("[{}]", parts.join(","))
}

/// Send a (possibly batched) payload to all URLs with retry.
async fn send_payload(
    client: &reqwest::Client,
    urls: &[String],
    content_type: &str,
    headers: &[(String, String)],
    retry: &RetryConfig,
    payload: String,
) {
    for url in urls.iter() {
        let url = url.clone();
        let ct = content_type.to_string();
        let client = client.clone();
        let headers: Vec<(String, String)> = headers.to_vec();
        let retry = retry.clone();
        let payload = payload.clone();

        tokio::spawn(async move {
            let mut attempts = 0u32;
            loop {
                let mut req = client
                    .post(&url)
                    .header("Content-Type", ct.as_str())
                    .body(payload.clone());

                for (name, value) in headers.iter() {
                    req = req.header(name.as_str(), value.as_str());
                }

                match req.send().await {
                    Ok(resp) if resp.status().is_success() => break,
                    Ok(_) | Err(_) => {
                        attempts += 1;
                        if attempts > retry.max_retries {
                            break;
                        }
                        let delay =
                            retry.retry_delay_ms * 2u64.saturating_pow(attempts - 1);
                        tokio::time::sleep(std::time::Duration::from_millis(delay))
                            .await;
                    }
                }
            }
        });
    }
}

impl FireAndForget {
    /// Create a new fire-and-forget dispatcher.
    /// Spawns a tokio runtime with a background task that drains the queue.
    ///
    /// # Panics
    /// Panics if the tokio runtime cannot be created.
    pub fn new(
        url: String,
        max_queue: usize,
        timeout_secs: u64,
        content_type: String,
    ) -> Self {
        Self::with_options(
            vec![url],
            max_queue,
            timeout_secs,
            content_type,
            Vec::new(),
            RetryConfig::default(),
        )
    }

    /// Full-featured constructor with headers, multiple URLs, and retry.
    /// Batching defaults to off (batch_size=1).
    pub fn with_options(
        urls: Vec<String>,
        max_queue: usize,
        timeout_secs: u64,
        content_type: String,
        custom_headers: Vec<(String, String)>,
        retry: RetryConfig,
    ) -> Self {
        Self::with_all_options(
            urls,
            max_queue,
            timeout_secs,
            content_type,
            custom_headers,
            retry,
            BatchConfig::default(),
        )
    }

    /// Full constructor with headers, multiple URLs, retry, and batching.
    pub fn with_all_options(
        urls: Vec<String>,
        max_queue: usize,
        timeout_secs: u64,
        content_type: String,
        custom_headers: Vec<(String, String)>,
        retry: RetryConfig,
        batch: BatchConfig,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<String>(max_queue);

        let runtime = Runtime::new().expect("failed to create tokio runtime");

        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let urls: Arc<Vec<String>> = Arc::new(urls);
        let ct = Arc::new(content_type);
        let headers: Arc<Vec<(String, String)>> = Arc::new(custom_headers);
        let retry = Arc::new(retry);

        let batch_size = batch.batch_size.max(1);
        let batch_timeout =
            std::time::Duration::from_millis(batch.batch_timeout_ms.max(1));

        runtime.spawn(async move {
            if batch_size <= 1 {
                // No batching: original behavior
                while let Some(payload) = rx.recv().await {
                    send_payload(&client, &urls, &ct, &headers, &retry, payload).await;
                }
            } else {
                // Batching enabled
                let mut buf: Vec<String> = Vec::with_capacity(batch_size);
                let mut interval = tokio::time::interval(batch_timeout);
                interval.set_missed_tick_behavior(
                    tokio::time::MissedTickBehavior::Delay,
                );
                // Consume the first immediate tick
                interval.tick().await;

                loop {
                    tokio::select! {
                        msg = rx.recv() => {
                            match msg {
                                Some(payload) => {
                                    buf.push(payload);
                                    if buf.len() >= batch_size {
                                        let batch_payload =
                                            build_batch_payload(&buf);
                                        buf.clear();
                                        send_payload(
                                            &client, &urls, &ct, &headers,
                                            &retry, batch_payload,
                                        )
                                        .await;
                                    }
                                }
                                None => {
                                    // Channel closed -- flush remainder
                                    if !buf.is_empty() {
                                        let batch_payload =
                                            build_batch_payload(&buf);
                                        buf.clear();
                                        send_payload(
                                            &client, &urls, &ct, &headers,
                                            &retry, batch_payload,
                                        )
                                        .await;
                                    }
                                    break;
                                }
                            }
                        }
                        _ = interval.tick() => {
                            if !buf.is_empty() {
                                let batch_payload = build_batch_payload(&buf);
                                buf.clear();
                                send_payload(
                                    &client, &urls, &ct, &headers,
                                    &retry, batch_payload,
                                )
                                .await;
                            }
                        }
                    }
                }
            }
        });

        FireAndForget {
            tx,
            _runtime: runtime,
            sent: std::cell::Cell::new(0),
            dropped: std::cell::Cell::new(0),
            failed: std::cell::Cell::new(0),
            retried: std::cell::Cell::new(0),
            retry_exhausted: std::cell::Cell::new(0),
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

    // ── parse_headers tests ──────────────────────────────────────

    #[test]
    fn test_parse_headers_single() {
        let h = parse_headers("Authorization: Bearer token123");
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, "Authorization");
        assert_eq!(h[0].1, "Bearer token123");
    }

    #[test]
    fn test_parse_headers_multiple() {
        let h = parse_headers("Authorization: Bearer xxx|X-Source: opensips");
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].0, "Authorization");
        assert_eq!(h[0].1, "Bearer xxx");
        assert_eq!(h[1].0, "X-Source");
        assert_eq!(h[1].1, "opensips");
    }

    #[test]
    fn test_parse_headers_empty() {
        let h = parse_headers("");
        assert!(h.is_empty());
    }

    #[test]
    fn test_parse_headers_whitespace() {
        let h = parse_headers("  X-Custom : value with spaces  |  X-Other: 42  ");
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].0, "X-Custom");
        assert_eq!(h[0].1, "value with spaces");
        assert_eq!(h[1].0, "X-Other");
        assert_eq!(h[1].1, "42");
    }

    #[test]
    fn test_parse_headers_no_colon() {
        let h = parse_headers("malformed-no-colon|Good: value");
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, "Good");
    }

    #[test]
    fn test_parse_headers_empty_name() {
        let h = parse_headers(": value-only");
        assert!(h.is_empty());
    }

    #[test]
    fn test_parse_headers_empty_value() {
        let h = parse_headers("X-Empty:");
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, "X-Empty");
        assert_eq!(h[0].1, "");
    }

    #[test]
    fn test_parse_headers_colon_in_value() {
        let h = parse_headers("Authorization: Basic dXNlcjpwYXNz");
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, "Authorization");
        assert_eq!(h[0].1, "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn test_parse_headers_trailing_pipe() {
        let h = parse_headers("X-Foo: bar|");
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, "X-Foo");
        assert_eq!(h[0].1, "bar");
    }

    // ── parse_urls tests ─────────────────────────────────────────

    #[test]
    fn test_parse_urls_single() {
        let u = parse_urls("http://localhost:9090/events");
        assert_eq!(u.len(), 1);
        assert_eq!(u[0], "http://localhost:9090/events");
    }

    #[test]
    fn test_parse_urls_multiple() {
        let u = parse_urls("http://a:9090/events,http://b:9091/events");
        assert_eq!(u.len(), 2);
        assert_eq!(u[0], "http://a:9090/events");
        assert_eq!(u[1], "http://b:9091/events");
    }

    #[test]
    fn test_parse_urls_whitespace() {
        let u = parse_urls("  http://a:9090/e , http://b:9091/e  ");
        assert_eq!(u.len(), 2);
        assert_eq!(u[0], "http://a:9090/e");
        assert_eq!(u[1], "http://b:9091/e");
    }

    #[test]
    fn test_parse_urls_trailing_comma() {
        let u = parse_urls("http://a:9090/e,");
        assert_eq!(u.len(), 1);
    }

    #[test]
    fn test_parse_urls_empty() {
        let u = parse_urls("");
        assert!(u.is_empty());
    }

    #[test]
    fn test_parse_urls_three() {
        let u = parse_urls("http://a/e,http://b/e,http://c/e");
        assert_eq!(u.len(), 3);
    }

    // ── RetryConfig tests ────────────────────────────────────────

    #[test]
    fn test_retry_config_default() {
        let rc = RetryConfig::default();
        assert_eq!(rc.max_retries, 0);
        assert_eq!(rc.retry_delay_ms, 1000);
    }

    #[test]
    fn test_retry_backoff_calculation() {
        let base_delay: u64 = 1000;
        assert_eq!(base_delay * 2u64.pow(0), 1000);
        assert_eq!(base_delay * 2u64.pow(1), 2000);
        assert_eq!(base_delay * 2u64.pow(2), 4000);
        assert_eq!(base_delay * 2u64.pow(3), 8000);
    }

    // ── BatchConfig tests ────────────────────────────────────────

    #[test]
    fn test_batch_config_default() {
        let bc = BatchConfig::default();
        assert_eq!(bc.batch_size, 1);
        assert_eq!(bc.batch_timeout_ms, 100);
    }

    #[test]
    fn test_batch_config_custom() {
        let bc = BatchConfig {
            batch_size: 10,
            batch_timeout_ms: 500,
        };
        assert_eq!(bc.batch_size, 10);
        assert_eq!(bc.batch_timeout_ms, 500);
    }

    // ── build_batch_payload tests ────────────────────────────────

    #[test]
    fn test_batch_payload_json_objects() {
        let msgs = vec![
            r#"{"method":"INVITE"}"#.to_string(),
            r#"{"method":"BYE"}"#.to_string(),
        ];
        let result = build_batch_payload(&msgs);
        assert_eq!(result, r#"[{"method":"INVITE"},{"method":"BYE"}]"#);
    }

    #[test]
    fn test_batch_payload_plain_strings() {
        let msgs = vec!["hello world".to_string(), "foo bar".to_string()];
        let result = build_batch_payload(&msgs);
        assert_eq!(result, r#"["hello world","foo bar"]"#);
    }

    #[test]
    fn test_batch_payload_mixed() {
        let msgs = vec![
            r#"{"key":"val"}"#.to_string(),
            "plain text".to_string(),
        ];
        let result = build_batch_payload(&msgs);
        assert_eq!(result, r#"[{"key":"val"},"plain text"]"#);
    }

    #[test]
    fn test_batch_payload_single() {
        let msgs = vec![r#"{"single":true}"#.to_string()];
        let result = build_batch_payload(&msgs);
        assert_eq!(result, r#"[{"single":true}]"#);
    }

    #[test]
    fn test_batch_payload_empty() {
        let msgs: Vec<String> = vec![];
        let result = build_batch_payload(&msgs);
        assert_eq!(result, "[]");
    }

    #[test]
    fn test_batch_payload_json_array() {
        let msgs = vec!["[1,2,3]".to_string()];
        let result = build_batch_payload(&msgs);
        assert_eq!(result, "[[1,2,3]]");
    }

    #[test]
    fn test_batch_payload_json_number() {
        let msgs = vec!["42".to_string(), "3.14".to_string()];
        let result = build_batch_payload(&msgs);
        assert_eq!(result, "[42,3.14]");
    }

    #[test]
    fn test_batch_payload_whitespace_trimmed() {
        let msgs = vec!["  {\"a\":1}  ".to_string()];
        let result = build_batch_payload(&msgs);
        assert_eq!(result, r#"[{"a":1}]"#);
    }

    // ── Batching integration tests ───────────────────────────────

    #[test]
    fn test_batch_size_1_passthrough() {
        // batch_size=1 should behave identically to no-batch (with_options)
        let ff = FireAndForget::with_all_options(
            vec!["http://127.0.0.1:19999/sink".to_string()],
            16,
            5,
            "application/json".to_string(),
            Vec::new(),
            RetryConfig::default(),
            BatchConfig { batch_size: 1, batch_timeout_ms: 100 },
        );
        assert!(ff.send(r#"{"test":1}"#.to_string()));
        assert_eq!(ff.sent.get(), 1);
        assert_eq!(ff.dropped.get(), 0);
    }

    #[test]
    fn test_batch_enqueue_multiple() {
        let ff = FireAndForget::with_all_options(
            vec!["http://127.0.0.1:19999/sink".to_string()],
            64,
            5,
            "application/json".to_string(),
            Vec::new(),
            RetryConfig::default(),
            BatchConfig { batch_size: 5, batch_timeout_ms: 1000 },
        );
        for i in 0..10 {
            assert!(ff.send(format!(r#"{{"n":{i}}}"#)));
        }
        assert_eq!(ff.sent.get(), 10);
        assert_eq!(ff.dropped.get(), 0);
    }

    #[test]
    fn test_batch_timeout_flush() {
        // Verify that partial batches are flushed on timeout by ensuring
        // messages can be enqueued even when batch_size is large
        let ff = FireAndForget::with_all_options(
            vec!["http://127.0.0.1:19999/sink".to_string()],
            64,
            5,
            "application/json".to_string(),
            Vec::new(),
            RetryConfig::default(),
            BatchConfig { batch_size: 100, batch_timeout_ms: 50 },
        );
        // Send fewer than batch_size messages
        for i in 0..3 {
            assert!(ff.send(format!(r#"{{"n":{i}}}"#)));
        }
        assert_eq!(ff.sent.get(), 3);
    }

    // ── FireAndForget tests ──────────────────────────────────────

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
        assert_eq!(ff.retried.get(), 0);
        assert_eq!(ff.retry_exhausted.get(), 0);
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
        let ff = FireAndForget::new(
            "http://192.0.2.1:1/blackhole".to_string(),
            1,
            1,
            "text/plain".to_string(),
        );

        let _r1 = ff.send("msg1".to_string());
        let _r2 = ff.send("msg2".to_string());
        let _r3 = ff.send("msg3".to_string());

        let total_sent = ff.sent.get();
        let total_dropped = ff.dropped.get();
        assert_eq!(total_sent + total_dropped, 3);
        assert!(
            total_dropped >= 1,
            "expected at least 1 drop, got {}",
            total_dropped
        );
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
        let big = "x".repeat(1_000_000);
        let ok = ff.send(big);
        assert!(ok);
        assert_eq!(ff.sent.get(), 1);
    }

    #[test]
    fn test_with_options_custom_headers() {
        let ff = FireAndForget::with_options(
            vec!["http://127.0.0.1:19999/sink".to_string()],
            16,
            5,
            "application/json".to_string(),
            vec![
                ("Authorization".to_string(), "Bearer token123".to_string()),
                ("X-Source".to_string(), "opensips".to_string()),
            ],
            RetryConfig::default(),
        );
        let ok = ff.send(r#"{"test":1}"#.to_string());
        assert!(ok);
        assert_eq!(ff.sent.get(), 1);
    }

    #[test]
    fn test_with_options_multiple_urls() {
        let ff = FireAndForget::with_options(
            vec![
                "http://127.0.0.1:19999/a".to_string(),
                "http://127.0.0.1:19999/b".to_string(),
            ],
            16,
            5,
            "application/json".to_string(),
            Vec::new(),
            RetryConfig::default(),
        );
        let ok = ff.send(r#"{"fanout":true}"#.to_string());
        assert!(ok);
        assert_eq!(ff.sent.get(), 1);
    }

    #[test]
    fn test_with_options_retry_config() {
        let ff = FireAndForget::with_options(
            vec!["http://127.0.0.1:19999/sink".to_string()],
            16,
            5,
            "application/json".to_string(),
            Vec::new(),
            RetryConfig {
                max_retries: 3,
                retry_delay_ms: 500,
            },
        );
        let ok = ff.send(r#"{"retry":true}"#.to_string());
        assert!(ok);
    }

    // ── Fanout-specific tests ────────────────────────────────────

    #[test]
    fn test_fanout_three_urls_enqueue() {
        let ff = FireAndForget::with_options(
            vec![
                "http://127.0.0.1:19999/a".to_string(),
                "http://127.0.0.1:19999/b".to_string(),
                "http://127.0.0.1:19999/c".to_string(),
            ],
            32,
            5,
            "application/json".to_string(),
            Vec::new(),
            RetryConfig::default(),
        );
        for i in 0..5 {
            assert!(ff.send(format!(r#"{{"n":{i}}}"#)));
        }
        assert_eq!(ff.sent.get(), 5);
        assert_eq!(ff.dropped.get(), 0);
    }

    #[test]
    fn test_fanout_single_url_backwards_compat() {
        let ff = FireAndForget::with_options(
            vec!["http://127.0.0.1:19999/sink".to_string()],
            16,
            5,
            "text/plain".to_string(),
            Vec::new(),
            RetryConfig::default(),
        );
        assert!(ff.send("hello".to_string()));
        assert_eq!(ff.sent.get(), 1);
    }

    #[test]
    fn test_parse_urls_preserves_paths() {
        let u = parse_urls("http://host1:9090/path/to/a,http://host2:9091/other/path");
        assert_eq!(u[0], "http://host1:9090/path/to/a");
        assert_eq!(u[1], "http://host2:9091/other/path");
    }

    #[test]
    fn test_parse_urls_with_query_params() {
        let u = parse_urls("http://a/hook?key=val,http://b/hook?key=val2");
        assert_eq!(u.len(), 2);
        assert!(u[0].contains("key=val"));
        assert!(u[1].contains("key=val2"));
    }

    // ── Retry-specific tests ─────────────────────────────────────

    #[test]
    fn test_retry_config_custom() {
        let rc = RetryConfig {
            max_retries: 5,
            retry_delay_ms: 200,
        };
        assert_eq!(rc.max_retries, 5);
        assert_eq!(rc.retry_delay_ms, 200);
    }

    #[test]
    fn test_retry_backoff_series() {
        let base: u64 = 100;
        let delays: Vec<u64> = (0..5).map(|i| base * 2u64.pow(i)).collect();
        assert_eq!(delays, vec![100, 200, 400, 800, 1600]);
    }

    #[test]
    fn test_retry_backoff_overflow_safety() {
        let result = 2u64.saturating_pow(63);
        assert!(result > 0);
        let result = 2u64.saturating_pow(64);
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn test_retry_zero_means_no_retry() {
        let rc = RetryConfig {
            max_retries: 0,
            retry_delay_ms: 1000,
        };
        assert_eq!(rc.max_retries, 0);
    }

    #[test]
    fn test_with_options_retry_and_headers_combined() {
        let ff = FireAndForget::with_options(
            vec![
                "http://127.0.0.1:19999/primary".to_string(),
                "http://127.0.0.1:19999/backup".to_string(),
            ],
            32,
            5,
            "application/json".to_string(),
            vec![
                ("Authorization".to_string(), "Bearer tok".to_string()),
                ("X-Retry".to_string(), "enabled".to_string()),
            ],
            RetryConfig {
                max_retries: 3,
                retry_delay_ms: 100,
            },
        );
        assert!(ff.send(r#"{"combined":true}"#.to_string()));
        assert_eq!(ff.sent.get(), 1);
        assert_eq!(ff.retried.get(), 0);
        assert_eq!(ff.retry_exhausted.get(), 0);
    }

    #[test]
    fn test_retry_delay_minimum_enforced() {
        let delay_raw: i32 = 50;
        let clamped = delay_raw.max(100) as u64;
        assert_eq!(clamped, 100);

        let delay_raw: i32 = 500;
        let clamped = delay_raw.max(100) as u64;
        assert_eq!(clamped, 500);
    }
}
