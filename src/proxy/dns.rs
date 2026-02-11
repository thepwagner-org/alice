use anyhow::Result;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use moka::future::Cache;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// DNS resolver with caching, overrides, and CIDR validation
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    cache: Cache<String, Arc<Vec<IpAddr>>>,
    /// Static hostname overrides (like /etc/hosts), bypasses DNS
    overrides: HashMap<String, Vec<IpAddr>>,
}

impl DnsResolver {
    pub async fn new(
        cache_ttl_secs: u64,
        cache_max_entries: u64,
        overrides: HashMap<String, Vec<IpAddr>>,
    ) -> Result<Self> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let cache = Cache::builder()
            .max_capacity(cache_max_entries)
            .time_to_live(Duration::from_secs(cache_ttl_secs))
            .build();

        if !overrides.is_empty() {
            debug!(count = overrides.len(), "loaded DNS host overrides");
        }

        Ok(Self {
            resolver,
            cache,
            overrides,
        })
    }

    /// Resolve a hostname to IP addresses (with caching).
    /// Checks static overrides first, then cache, then real DNS.
    pub async fn resolve(&self, host: &str) -> Result<Arc<Vec<IpAddr>>> {
        // Check overrides first (like /etc/hosts)
        if let Some(addrs) = self.overrides.get(host) {
            debug!(host = %host, addrs = ?addrs, "using DNS override");
            return Ok(Arc::new(addrs.clone()));
        }

        // Check cache
        if let Some(cached) = self.cache.get(host).await {
            return Ok(cached);
        }

        // Real DNS lookup
        let response = self.resolver.lookup_ip(host).await?;
        let addrs: Vec<IpAddr> = response.iter().collect();
        let addrs = Arc::new(addrs);

        self.cache
            .insert(host.to_string(), Arc::clone(&addrs))
            .await;
        Ok(addrs)
    }

    /// Check if a resolved address is a DNS blackhole (0.0.0.0 or ::)
    pub fn is_blackhole(addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        }
    }

    /// Check if any resolved address is suspicious (blackhole)
    ///
    /// DNS blackholes return 0.0.0.0 or :: to block domains. Connecting to these
    /// would fail anyway, so we reject early with a clear error.
    pub fn has_suspicious_addr(addrs: &[IpAddr]) -> bool {
        addrs.iter().any(Self::is_blackhole)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_is_blackhole() {
        assert!(DnsResolver::is_blackhole(&IpAddr::V4(Ipv4Addr::new(
            0, 0, 0, 0
        ))));
        assert!(!DnsResolver::is_blackhole(&IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        )))); // loopback is NOT blackhole
        assert!(!DnsResolver::is_blackhole(&IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
    }

    #[test]
    fn test_has_suspicious_addr() {
        // Contains blackhole
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        ];
        assert!(DnsResolver::has_suspicious_addr(&addrs));

        // No blackhole
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        ];
        assert!(!DnsResolver::has_suspicious_addr(&addrs));

        // Empty list
        assert!(!DnsResolver::has_suspicious_addr(&[]));
    }
}
