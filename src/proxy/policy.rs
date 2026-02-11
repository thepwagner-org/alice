use crate::config::{Action, Rule};
use anyhow::{anyhow, Context, Result};
use globset::{Glob, GlobMatcher};
use ipnet::IpNet;
use std::net::IpAddr;

/// Compiled policy rule - either host-based or CIDR-based
enum CompiledPattern {
    /// Host glob pattern with optional path pattern
    Host {
        host_matcher: GlobMatcher,
        path_matcher: Option<GlobMatcher>,
        /// Paths where OAuth tokens should be redacted from responses
        redact_paths: Vec<GlobMatcher>,
    },
    /// CIDR block matched against resolved IP addresses
    Cidr { network: IpNet },
}

/// Compiled policy rule
struct CompiledRule {
    action: Action,
    pattern: CompiledPattern,
}

/// Policy evaluation result
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub action: Action,
    pub rule_index: usize,
    /// True if this rule has a path pattern that wasn't evaluated yet
    pub needs_path_check: bool,
    /// True if this rule has redact_paths configured (requires full request inspection)
    pub has_redact_paths: bool,
    /// True if the matched path is in the rule's redact_paths list
    pub redact_tokens: bool,
}

/// Evaluates network policy rules
pub struct PolicyEngine {
    rules: Vec<CompiledRule>,
    /// True if any rules are CIDR-based (requires DNS resolution)
    has_cidr_rules: bool,
}

impl PolicyEngine {
    pub fn new(rules: &[Rule]) -> Result<Self> {
        let mut has_cidr_rules = false;

        let compiled = rules
            .iter()
            .enumerate()
            .map(|(i, rule)| {
                // Validate: must have exactly one of host or cidr
                match (&rule.host, &rule.cidr) {
                    (Some(host), None) => {
                        let host_glob = Glob::new(host).with_context(|| {
                            format!("invalid host glob in rule {}: {}", i, host)
                        })?;

                        let path_matcher = rule
                            .path
                            .as_ref()
                            .map(|p| {
                                Glob::new(p)
                                    .with_context(|| {
                                        format!("invalid path glob in rule {}: {}", i, p)
                                    })
                                    .map(|g| g.compile_matcher())
                            })
                            .transpose()?;

                        // Compile redact_paths globs
                        let redact_paths = rule
                            .redact_paths
                            .iter()
                            .enumerate()
                            .map(|(j, p)| {
                                Glob::new(p)
                                    .with_context(|| {
                                        format!(
                                            "invalid redact_paths glob in rule {}, index {}: {}",
                                            i, j, p
                                        )
                                    })
                                    .map(|g| g.compile_matcher())
                            })
                            .collect::<Result<Vec<_>>>()?;

                        // Validate: redact_paths only makes sense with action = allow
                        if !redact_paths.is_empty() && rule.action != Action::Allow {
                            return Err(anyhow!(
                                "rule {}: redact_paths is only valid with action = 'allow'",
                                i
                            ));
                        }

                        Ok(CompiledRule {
                            action: rule.action,
                            pattern: CompiledPattern::Host {
                                host_matcher: host_glob.compile_matcher(),
                                path_matcher,
                                redact_paths,
                            },
                        })
                    }
                    (None, Some(cidr)) => {
                        if rule.path.is_some() {
                            return Err(anyhow!(
                                "rule {}: 'path' is not valid with 'cidr' rules",
                                i
                            ));
                        }

                        let network: IpNet = cidr
                            .parse()
                            .with_context(|| format!("invalid CIDR in rule {}: {}", i, cidr))?;

                        has_cidr_rules = true;

                        Ok(CompiledRule {
                            action: rule.action,
                            pattern: CompiledPattern::Cidr { network },
                        })
                    }
                    (Some(_), Some(_)) => {
                        Err(anyhow!("rule {}: cannot specify both 'host' and 'cidr'", i))
                    }
                    (None, None) => {
                        Err(anyhow!("rule {}: must specify either 'host' or 'cidr'", i))
                    }
                }
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            rules: compiled,
            has_cidr_rules,
        })
    }

    /// Returns true if any CIDR rules exist (requires DNS resolution before evaluation)
    pub fn has_cidr_rules(&self) -> bool {
        self.has_cidr_rules
    }

    /// Evaluate policy for a host only (at CONNECT time), with optional resolved IPs for CIDR rules.
    /// Returns the first matching rule, or default deny.
    pub fn evaluate_host(&self, host: &str, resolved_ips: Option<&[IpAddr]>) -> PolicyDecision {
        for (i, rule) in self.rules.iter().enumerate() {
            let matches = match &rule.pattern {
                CompiledPattern::Host { host_matcher, .. } => host_matcher.is_match(host),
                CompiledPattern::Cidr { network } => {
                    // CIDR rules require resolved IPs
                    resolved_ips
                        .map(|ips| ips.iter().any(|ip| network.contains(ip)))
                        .unwrap_or(false)
                }
            };

            if matches {
                let (needs_path_check, has_redact_paths) = match &rule.pattern {
                    CompiledPattern::Host {
                        path_matcher,
                        redact_paths,
                        ..
                    } => (path_matcher.is_some(), !redact_paths.is_empty()),
                    CompiledPattern::Cidr { .. } => (false, false),
                };

                return PolicyDecision {
                    action: rule.action,
                    rule_index: i,
                    needs_path_check,
                    has_redact_paths,
                    // Can't determine redact_tokens without path
                    redact_tokens: false,
                };
            }
        }

        // Default deny
        PolicyDecision {
            action: Action::Deny,
            rule_index: usize::MAX,
            needs_path_check: false,
            has_redact_paths: false,
            redact_tokens: false,
        }
    }

    /// Evaluate policy for host + path (after TLS inspection), with optional resolved IPs.
    /// Returns the first matching rule, or default deny.
    pub fn evaluate(
        &self,
        host: &str,
        path: &str,
        resolved_ips: Option<&[IpAddr]>,
    ) -> PolicyDecision {
        for (i, rule) in self.rules.iter().enumerate() {
            let (matches, redact_tokens) = match &rule.pattern {
                CompiledPattern::Host {
                    host_matcher,
                    path_matcher,
                    redact_paths,
                } => {
                    if !host_matcher.is_match(host) {
                        continue;
                    }

                    // If rule has path pattern, check it
                    if let Some(pm) = path_matcher {
                        if !pm.is_match(path) {
                            continue;
                        }
                    }

                    // Check if path matches any redact_paths pattern
                    let should_redact = redact_paths.iter().any(|rp| rp.is_match(path));

                    (true, should_redact)
                }
                CompiledPattern::Cidr { network } => {
                    // CIDR rules match regardless of path, no token redaction
                    let matches = resolved_ips
                        .map(|ips| ips.iter().any(|ip| network.contains(ip)))
                        .unwrap_or(false);
                    (matches, false)
                }
            };

            if matches {
                return PolicyDecision {
                    action: rule.action,
                    rule_index: i,
                    needs_path_check: false,
                    has_redact_paths: redact_tokens, // If we matched a redact path, the rule had redact_paths
                    redact_tokens,
                };
            }
        }

        // Default deny
        PolicyDecision {
            action: Action::Deny,
            rule_index: usize::MAX,
            needs_path_check: false,
            has_redact_paths: false,
            redact_tokens: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn host_rules(specs: &[(&str, Option<&str>, Action)]) -> Vec<Rule> {
        specs
            .iter()
            .map(|(host, path, action)| Rule {
                action: *action,
                host: Some(host.to_string()),
                path: path.map(|s| s.to_string()),
                cidr: None,
                redact_paths: vec![],
            })
            .collect()
    }

    fn cidr_rule(cidr: &str, action: Action) -> Rule {
        Rule {
            action,
            host: None,
            path: None,
            cidr: Some(cidr.to_string()),
            redact_paths: vec![],
        }
    }

    #[test]
    fn test_exact_host_match() {
        let engine =
            PolicyEngine::new(&host_rules(&[("api.httpbin.org", None, Action::Allow)])).unwrap();

        let decision = engine.evaluate_host("api.httpbin.org", None);
        assert_eq!(decision.action, Action::Allow);
        assert_eq!(decision.rule_index, 0);

        let decision = engine.evaluate_host("other.com", None);
        assert_eq!(decision.action, Action::Deny);
    }

    #[test]
    fn test_wildcard_host() {
        let engine =
            PolicyEngine::new(&host_rules(&[("*.httpbin.org", None, Action::Allow)])).unwrap();

        let decision = engine.evaluate_host("api.httpbin.org", None);
        assert_eq!(decision.action, Action::Allow);

        let decision = engine.evaluate_host("www.httpbin.org", None);
        assert_eq!(decision.action, Action::Allow);

        // Doesn't match bare domain
        let decision = engine.evaluate_host("httpbin.org", None);
        assert_eq!(decision.action, Action::Deny);
    }

    #[test]
    fn test_path_matching() {
        let engine = PolicyEngine::new(&host_rules(&[
            ("api.example.com", Some("/v1/*"), Action::Allow),
            ("api.example.com", Some("/admin/*"), Action::Deny),
            ("api.example.com", None, Action::Allow), // fallback for other paths
        ]))
        .unwrap();

        let decision = engine.evaluate("api.example.com", "/v1/users", None);
        assert_eq!(decision.action, Action::Allow);
        assert_eq!(decision.rule_index, 0);

        let decision = engine.evaluate("api.example.com", "/admin/delete", None);
        assert_eq!(decision.action, Action::Deny);
        assert_eq!(decision.rule_index, 1);

        let decision = engine.evaluate("api.example.com", "/other", None);
        assert_eq!(decision.action, Action::Allow);
        assert_eq!(decision.rule_index, 2);
    }

    #[test]
    fn test_first_match_wins() {
        let engine = PolicyEngine::new(&host_rules(&[
            ("*.example.com", None, Action::Deny),
            ("api.example.com", None, Action::Allow), // never reached
        ]))
        .unwrap();

        let decision = engine.evaluate_host("api.example.com", None);
        assert_eq!(decision.action, Action::Deny);
        assert_eq!(decision.rule_index, 0);
    }

    #[test]
    fn test_needs_path_check() {
        let engine = PolicyEngine::new(&host_rules(&[(
            "api.example.com",
            Some("/v1/*"),
            Action::Allow,
        )]))
        .unwrap();

        let decision = engine.evaluate_host("api.example.com", None);
        assert!(decision.needs_path_check);
        assert_eq!(decision.action, Action::Allow); // tentative

        let decision = engine.evaluate("api.example.com", "/v1/foo", None);
        assert!(!decision.needs_path_check);
        assert_eq!(decision.action, Action::Allow);

        let decision = engine.evaluate("api.example.com", "/v2/foo", None);
        assert_eq!(decision.action, Action::Deny); // no match
    }

    // CIDR rule tests

    #[test]
    fn test_cidr_rule_deny_metadata() {
        // Block AWS metadata endpoint
        let rules = vec![
            cidr_rule("169.254.169.254/32", Action::Deny),
            Rule {
                action: Action::Allow,
                host: Some("*".to_string()),
                path: None,
                cidr: None,
                redact_paths: vec![],
            },
        ];
        let engine = PolicyEngine::new(&rules).unwrap();
        assert!(engine.has_cidr_rules());

        // Request to metadata IP should be denied
        let metadata_ip = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        let decision = engine.evaluate_host("evil.attacker.com", Some(&[metadata_ip]));
        assert_eq!(decision.action, Action::Deny);
        assert_eq!(decision.rule_index, 0);

        // Request to normal IP should be allowed by catch-all
        let normal_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)); // example.com
        let decision = engine.evaluate_host("example.com", Some(&[normal_ip]));
        assert_eq!(decision.action, Action::Allow);
        assert_eq!(decision.rule_index, 1);
    }

    #[test]
    fn test_cidr_rule_deny_private_ranges() {
        // Block RFC1918 private ranges
        let rules = vec![
            cidr_rule("10.0.0.0/8", Action::Deny),
            cidr_rule("172.16.0.0/12", Action::Deny),
            cidr_rule("192.168.0.0/16", Action::Deny),
            Rule {
                action: Action::Allow,
                host: Some("*".to_string()),
                path: None,
                cidr: None,
                redact_paths: vec![],
            },
        ];
        let engine = PolicyEngine::new(&rules).unwrap();

        // 10.x.x.x should be denied
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        let decision = engine.evaluate_host("internal.corp", Some(&[ip]));
        assert_eq!(decision.action, Action::Deny);

        // 172.16.x.x should be denied
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let decision = engine.evaluate_host("internal.corp", Some(&[ip]));
        assert_eq!(decision.action, Action::Deny);

        // 172.15.x.x should be allowed (not in 172.16.0.0/12)
        let ip = IpAddr::V4(Ipv4Addr::new(172, 15, 0, 1));
        let decision = engine.evaluate_host("external.com", Some(&[ip]));
        assert_eq!(decision.action, Action::Allow);

        // 192.168.x.x should be denied
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let decision = engine.evaluate_host("home.local", Some(&[ip]));
        assert_eq!(decision.action, Action::Deny);

        // Public IP should be allowed
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let decision = engine.evaluate_host("dns.google", Some(&[ip]));
        assert_eq!(decision.action, Action::Allow);
    }

    #[test]
    fn test_cidr_multiple_resolved_ips() {
        // If any resolved IP is in a blocked range, deny
        let rules = vec![
            cidr_rule("10.0.0.0/8", Action::Deny),
            Rule {
                action: Action::Allow,
                host: Some("*".to_string()),
                path: None,
                cidr: None,
                redact_paths: vec![],
            },
        ];
        let engine = PolicyEngine::new(&rules).unwrap();

        // Multiple IPs, one is private -> should deny
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // public
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),      // private
        ];
        let decision = engine.evaluate_host("dual-homed.example.com", Some(&ips));
        assert_eq!(decision.action, Action::Deny);

        // All public IPs -> should allow
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)),
        ];
        let decision = engine.evaluate_host("example.com", Some(&ips));
        assert_eq!(decision.action, Action::Allow);
    }

    #[test]
    fn test_rule_validation_errors() {
        // Both host and cidr
        let rules = vec![Rule {
            action: Action::Allow,
            host: Some("example.com".to_string()),
            path: None,
            cidr: Some("10.0.0.0/8".to_string()),
            redact_paths: vec![],
        }];
        assert!(PolicyEngine::new(&rules).is_err());

        // Neither host nor cidr
        let rules = vec![Rule {
            action: Action::Allow,
            host: None,
            path: None,
            cidr: None,
            redact_paths: vec![],
        }];
        assert!(PolicyEngine::new(&rules).is_err());

        // Path with cidr (invalid)
        let rules = vec![Rule {
            action: Action::Allow,
            host: None,
            path: Some("/api/*".to_string()),
            cidr: Some("10.0.0.0/8".to_string()),
            redact_paths: vec![],
        }];
        assert!(PolicyEngine::new(&rules).is_err());
    }
}
