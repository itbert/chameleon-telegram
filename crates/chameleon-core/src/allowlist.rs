use crate::error::{Error, Result};
use ipnet::IpNet;
use std::net::IpAddr;
use tokio::net::lookup_host;

#[derive(Debug, Clone)]
pub struct AllowList {
    allow_all: bool,
    cidrs: Vec<IpNet>,
    domains: Vec<String>,
}

impl AllowList {
    pub fn new(allow_all: bool, cidrs: Vec<String>, domains: Vec<String>) -> Result<Self> {
        let mut parsed = Vec::new();
        for c in cidrs {
            let net: IpNet = c
                .parse()
                .map_err(|e| Error::Allowlist(format!("invalid cidr {c}: {e}")))?;
            parsed.push(net);
        }
        let normalized_domains = domains
            .into_iter()
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();

        Ok(AllowList {
            allow_all,
            cidrs: parsed,
            domains: normalized_domains,
        })
    }

    pub async fn allows(&self, host: &str) -> Result<bool> {
        if self.allow_all {
            return Ok(true);
        }
        let host_norm = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host_norm.is_empty() {
            return Ok(false);
        }
        if let Ok(ip) = host_norm.parse::<IpAddr>() {
            return Ok(self.allows_ip(ip));
        }
        if self.allows_domain(&host_norm) {
            return Ok(true);
        }
        if self.cidrs.is_empty() {
            return Ok(false);
        }
        let addrs = lookup_host((host_norm.as_str(), 0))
            .await
            .map_err(|e| Error::Allowlist(format!("dns lookup failed: {e}")))?;
        for addr in addrs {
            if self.allows_ip(addr.ip()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn allows_ip(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|net| net.contains(&ip))
    }

    fn allows_domain(&self, host: &str) -> bool {
        self.domains.iter().any(|d| host == d || host.ends_with(&format!(".{d}")))
    }
}
