//! Optional cross-node state replication via OpenSIPS clusterer.
//!
//! Only initialized when cluster_id > 0. When disabled, zero overhead.
//! Full bin_packet FFI integration is deferred — this provides the API shape.

/// Cluster sync handle. Created per service module.
pub struct ClusterSync {
    cluster_id: i32,
}

impl ClusterSync {
    /// Create a new ClusterSync. Returns None if cluster_id <= 0 (disabled).
    pub fn new(cluster_id: i32) -> Option<Self> {
        if cluster_id <= 0 {
            return None;
        }
        Some(ClusterSync { cluster_id })
    }

    /// Whether clustering is enabled.
    pub fn is_enabled(&self) -> bool {
        self.cluster_id > 0
    }

    /// Get the cluster ID.
    pub fn cluster_id(&self) -> i32 {
        self.cluster_id
    }

    /// Placeholder: broadcast state change to cluster peers.
    /// Full implementation requires bin_packet_t FFI from clusterer module.
    pub fn broadcast(&self, _data: &[u8]) {
        // TODO: implement when clusterer FFI bindings are added
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_disabled() {
        assert!(ClusterSync::new(0).is_none());
        assert!(ClusterSync::new(-1).is_none());
    }

    #[test]
    fn test_cluster_enabled() {
        let cs = ClusterSync::new(1).unwrap();
        assert!(cs.is_enabled());
        assert_eq!(cs.cluster_id(), 1);
    }
}
