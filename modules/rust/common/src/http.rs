//! HTTP connection pool builder using rustls (never system `OpenSSL`).
//!
//! Each service module creates its own pool with its own config.
//! The pool is created once per worker in child_init via OnceLock.

use std::sync::OnceLock;
use std::time::Duration;

/// Per-worker HTTP client pool. Created in child_init, reused for all requests.
pub struct Pool {
    client: OnceLock<reqwest::blocking::Client>,
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Pool {
    pub const fn new() -> Self {
        Pool { client: OnceLock::new() }
    }

    /// Initialize the pool. Call once from child_init.
    /// timeout_secs: per-request timeout.
    /// pool_size: max idle connections per host.
    /// ca_file: optional path to custom CA certificate (added to system CAs).
    pub fn init(&self, timeout_secs: i32, pool_size: i32, ca_file: Option<&str>) {
        let timeout = Duration::from_secs(if timeout_secs > 0 { timeout_secs as u64 } else { 2 });
        let size = if pool_size > 0 { pool_size as usize } else { 4 };

        let mut builder = reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .timeout(timeout)
            .pool_max_idle_per_host(size)
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent("OpenSIPS-Rust/0.1");

        // Add custom CA if provided
        if let Some(path) = ca_file {
            if let Ok(pem) = std::fs::read(path) {
                if let Ok(cert) = reqwest::Certificate::from_pem(&pem) {
                    builder = builder.add_root_certificate(cert);
                }
            }
        }

        let client = builder.build().unwrap_or_else(|_| reqwest::blocking::Client::new());

        if self.client.set(client).is_err() {
            // Already initialized (worker reuse) -- safe to ignore
        }
    }

    /// Get the HTTP client. Returns None if init() was not called.
    pub fn get(&self) -> Option<&reqwest::blocking::Client> {
        self.client.get()
    }

    /// HTTP GET, return body as string.
    pub fn get_url(&self, url: &str) -> Result<(u16, String), String> {
        let client = self.get().ok_or("HTTP pool not initialized")?;
        let resp = client.get(url).send().map_err(|e| format!("HTTP GET failed: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().map_err(|e| format!("body read failed: {e}"))?;
        Ok((status, body))
    }

    /// HTTP POST with string body, return status + response body.
    pub fn post_url(&self, url: &str, body: &str, content_type: &str) -> Result<(u16, String), String> {
        let client = self.get().ok_or("HTTP pool not initialized")?;
        let resp = client.post(url)
            .header("Content-Type", content_type)
            .body(body.to_string())
            .send()
            .map_err(|e| format!("HTTP POST failed: {e}"))?;
        let status = resp.status().as_u16();
        let resp_body = resp.text().map_err(|e| format!("body read failed: {e}"))?;
        Ok((status, resp_body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_new() {
        let pool = Pool::new();
        assert!(pool.get().is_none());
    }

    #[test]
    fn test_pool_init() {
        let pool = Pool::new();
        pool.init(5, 4, None);
        assert!(pool.get().is_some());
    }

    #[test]
    fn test_pool_double_init() {
        let pool = Pool::new();
        pool.init(5, 4, None);
        pool.init(10, 8, None); // second init silently ignored by OnceLock
        assert!(pool.get().is_some());
    }

    #[test]
    fn test_pool_get_url_not_initialized() {
        let pool = Pool::new();
        let result = pool.get_url("http://example.com");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "HTTP pool not initialized");
    }

    #[test]
    fn test_pool_post_url_not_initialized() {
        let pool = Pool::new();
        let result = pool.post_url("http://example.com", "{}", "application/json");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "HTTP pool not initialized");
    }

    #[test]
    fn test_pool_init_negative_values() {
        // Negative timeout/pool_size should fall back to defaults (2s, 4)
        let pool = Pool::new();
        pool.init(-1, -1, None);
        assert!(pool.get().is_some());
    }

    #[test]
    fn test_pool_init_with_nonexistent_ca() {
        // Non-existent CA file should not panic, just skip
        let pool = Pool::new();
        pool.init(2, 4, Some("/tmp/nonexistent_ca.pem"));
        assert!(pool.get().is_some());
    }

    #[test]
    #[ignore] // requires network
    fn test_pool_get_url_live() {
        let pool = Pool::new();
        pool.init(10, 4, None);
        let result = pool.get_url("https://httpbin.org/get");
        assert!(result.is_ok());
        let (status, _body) = result.unwrap();
        assert_eq!(status, 200);
    }
}
