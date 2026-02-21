use crate::error::{Error, Result};
use ipnet::IpNet;
use std::net::IpAddr;
use tokio::net::lookup_host;

#[derive(Debug, Clone, Copy)]
pub struct HostPolicy {
    pub deny_private_targets: bool,
    pub allow_loopback_targets: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostDecision {
    Allowed,
    Denied,
    DeniedPrivate,
}

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
        let mut normalized_domains = Vec::new();
        for domain in domains {
            let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if normalized.is_empty() {
                continue;
            }
            if !is_valid_ascii_domain(&normalized) {
                return Err(Error::Allowlist(format!(
                    "invalid allow domain: {domain}"
                )));
            }
            normalized_domains.push(normalized);
        }

        Ok(AllowList {
            allow_all,
            cidrs: parsed,
            domains: normalized_domains,
        })
    }

    pub async fn allows(&self, host: &str) -> Result<bool> {
        let policy = HostPolicy {
            deny_private_targets: false,
            allow_loopback_targets: true,
        };
        Ok(matches!(
            self.evaluate(host, policy).await?,
            HostDecision::Allowed
        ))
    }

    pub async fn evaluate(&self, host: &str, policy: HostPolicy) -> Result<HostDecision> {
        let host_norm = normalize_host(host)?;
        if let Ok(ip) = host_norm.parse::<IpAddr>() {
            if policy.deny_private_targets
                && is_private_or_special(ip, policy.allow_loopback_targets)
            {
                return Ok(HostDecision::DeniedPrivate);
            }
            if self.allow_all {
                return Ok(HostDecision::Allowed);
            }
            return Ok(if self.allows_ip(ip) {
                HostDecision::Allowed
            } else {
                HostDecision::Denied
            });
        }

        if policy.deny_private_targets {
            let addrs = lookup_host((host_norm.as_str(), 0))
                .await
                .map_err(|e| Error::Allowlist(format!("dns lookup failed: {e}")))?;
            for addr in addrs {
                if is_private_or_special(addr.ip(), policy.allow_loopback_targets) {
                    return Ok(HostDecision::DeniedPrivate);
                }
            }
        }

        if self.allow_all {
            return Ok(HostDecision::Allowed);
        }
        if self.allows_domain(&host_norm) {
            return Ok(HostDecision::Allowed);
        }
        if self.cidrs.is_empty() {
            return Ok(HostDecision::Denied);
        }
        let addrs = lookup_host((host_norm.as_str(), 0))
            .await
            .map_err(|e| Error::Allowlist(format!("dns lookup failed: {e}")))?;
        for addr in addrs {
            if self.allows_ip(addr.ip()) {
                return Ok(HostDecision::Allowed);
            }
        }
        Ok(HostDecision::Denied)
    }

    fn allows_ip(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|net| net.contains(&ip))
    }

    fn allows_domain(&self, host: &str) -> bool {
        self.domains.iter().any(|d| host == d || host.ends_with(&format!(".{d}")))
    }
}

pub fn normalize_host(host: &str) -> Result<String> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(Error::Allowlist("host is empty".into()));
    }
    if normalized.parse::<IpAddr>().is_ok() {
        return Ok(normalized);
    }
    if !is_valid_ascii_domain(&normalized) {
        return Err(Error::Allowlist("host is not a valid ASCII domain".into()));
    }
    Ok(normalized)
}

fn is_valid_ascii_domain(host: &str) -> bool {
    if host.len() > 253 {
        return false;
    }
    if !host.is_ascii() {
        return false;
    }
    if host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    let mut label_count = 0usize;
    for label in host.split('.') {
        label_count += 1;
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return false;
        }
    }
    label_count >= 2
}

pub fn is_private_or_special(ip: IpAddr, allow_loopback_targets: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if !allow_loopback_targets && v4.is_loopback() {
                return true;
            }
            v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            if !allow_loopback_targets && v6.is_loopback() {
                return true;
            }
            v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}
