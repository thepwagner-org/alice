# Security Model

Alice is a sanitizing HTTPS proxy that restricts network access for untrusted clients. This document describes the threat model, security guarantees, and known limitations.

## Threat Model

### Principals

- **Alice** - The proxy, assumed to be trusted and correctly configured
- **Bob** - The client connecting through Alice, assumed to be *untrusted* or *semi-trusted*
- **Eve** - A local attacker with access to the same system as Alice
- **Upstream servers** - Internet hosts that Bob wants to reach

### What Alice Protects Against

**1. Unauthorized network access**

Bob can only reach hosts/paths explicitly allowed by policy rules. All other requests are denied at the proxy level before any upstream connection is made.

- Default deny: no rules = no access
- First-match-wins semantics (like firewall rules)
- Glob patterns for host and path matching

**2. Policy bypass via TLS**

Without MITM inspection, Bob could tunnel arbitrary traffic through CONNECT and Alice couldn't inspect the HTTP request paths. Alice performs TLS interception:

- Generates a per-host certificate signed by Alice's CA
- Bob must trust Alice's CA (controlled by whoever provisions Bob)
- Alice terminates Bob's TLS, inspects HTTP, then makes a separate TLS connection upstream

**3. Plain HTTP exfiltration**

Alice only supports HTTPS (CONNECT method). Plain HTTP requests return 501 Not Implemented. This prevents Bob from accidentally or intentionally sending sensitive data over unencrypted connections.

**4. Unauthorized proxy access**

Optional proxy authentication (HTTP Basic over the CONNECT request) restricts who can use the proxy. Without valid credentials, requests receive 407 Proxy Authentication Required.

### What Alice Does NOT Protect Against

**1. Malicious upstream servers**

Alice does not inspect response content (Phase 1). A malicious allowed host could return harmful data. Future phases may add response inspection.

**2. DNS rebinding attacks (mitigated with CIDR rules)**

If an attacker controls a hostname's DNS, they could:
- Initially resolve to a legitimate IP (passing host-based policy)
- Later resolve to an internal IP (e.g., 169.254.169.254 for cloud metadata)

Alice mitigates this with **CIDR rules** that check resolved IP addresses:

```toml
# Block cloud metadata endpoints
[[rules]]
action = "deny"
cidr = "169.254.169.254/32"

# Block RFC1918 private ranges
[[rules]]
action = "deny"
cidr = "10.0.0.0/8"

[[rules]]
action = "deny"
cidr = "172.16.0.0/12"

[[rules]]
action = "deny"
cidr = "192.168.0.0/16"
```

When CIDR rules are configured:
- DNS is resolved at CONNECT time
- Resolved IPs are checked against CIDR rules before allowing the connection
- The same resolved IP is used for the upstream connection (no TOCTOU gap)

**3. IP-based access**

Alice matches on hostname, not IP. Bob cannot connect directly to IP addresses through the proxy (no Host header in CONNECT to IP).

**4. Timing/side-channel attacks**

An observer watching traffic patterns could infer which hosts Bob communicates with (by timing, packet sizes, etc.) even though content is encrypted between Bob and Alice.

**5. Compromised Alice**

If Alice itself is compromised, all security guarantees are void. Alice sees all plaintext HTTP traffic.

**6. Bob bypassing the proxy entirely**

Alice only protects traffic routed through it. If Bob has direct network access, they can bypass Alice. Enforcement requires network-level controls (firewall rules, network namespaces).

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                                 │
│  ┌───────────┐    ┌─────────────────────────────────────────┐  │
│  │  Config   │───►│              Alice                      │  │
│  │  (rules)  │    │  - Policy engine                        │  │
│  └───────────┘    │  - CA private key                       │  │
│                   │  - Proxy auth credentials               │  │
│  ┌───────────┐    │  - Upstream CA trust store              │  │
│  │  CA cert  │◄───│  - Injected credentials (in memory)     │  │
│  │  (public) │    └─────────────────────────────────────────┘  │
│  └───────────┘           ▲                │                    │
│       │                  │                │                    │
│       │           ┌──────┴──────┐         │                    │
│       │           │ Credentials │         │                    │
│       │           │ - env vars  │         │                    │
│       │           │ - files     │         │                    │
│       │           │ - SOPS      │         │                    │
│       │           └─────────────┘         │                    │
└───────┼───────────────────────────────────┼────────────────────┘
        │                                   │
        ▼                                   ▼
┌───────────────┐   ┌───────────┐   ┌───────────────┐
│  SEMI-TRUSTED │   │   LOCAL   │   │   UNTRUSTED   │
│               │   │  ATTACKER │   │               │
│     Bob       │   │           │   │   Internet    │
│  (has CA cert │   │    Eve    │   │               │
│   only)       │   │           │   │               │
└───────────────┘   └───────────┘   └───────────────┘
        │                                   ▲
        └───────────── (through Alice) ─────┘
```

Bob only receives:
- Alice's CA certificate (to verify MITM'd connections)
- Proxy address and optional proxy auth credentials
- Dummy credential tokens (which get replaced by Alice)

Bob does NOT have access to:
- Policy rules (can only probe by trial and error)
- Alice's CA private key
- Real injected credentials (only sees dummy tokens in their own requests)
- Upstream responses from denied hosts

## Certificate Security

### CA Lifecycle

- CA keypair generated at proxy startup (not persisted by default)
- CA cert written to configured path for client distribution
- CA validity is short (default 6 hours) to limit exposure if compromised
- Per-host certs have even shorter validity (default 2 hours)

### Certificate Caching

Per-host certificates are cached in memory to avoid regeneration overhead. Cache entries expire before the certificate validity period ends.

### Upstream Verification

Alice verifies upstream server certificates against:
- System root CA store (webpki-roots)
- Optional additional CAs via `upstream_ca` config (for internal PKI)

## Policy Enforcement

### Evaluation Points

1. **CONNECT time (host + CIDR)**: 
   - If CIDR rules exist, DNS is resolved and IPs checked against CIDR deny rules
   - If host is definitely denied and no path rules apply, reject immediately with 403
2. **After TLS, before upstream request (host + path + CIDR)**: Full policy evaluation including path patterns and resolved IPs

### Path Inspection

- **HTTP/1.1**: Full request line inspection (method, path, version)
- **HTTP/2**: Full stream inspection via h2 crate; path-based rules work correctly
- **H2→H1.1 translation**: When upstream only supports HTTP/1.1, Alice translates

### Glob Pattern Security

- Patterns use `globset` crate (not regex)
- `*` matches any characters except path separators in paths
- `**` for recursive matching is NOT supported in host patterns
- Patterns are compiled at config load time; invalid patterns cause startup failure

## Connection Limits

Alice implements resource limits to prevent denial-of-service:

- **max_connections** (default 1000): Maximum concurrent connections. New connections wait briefly then are rejected if limit persists.
- **idle_timeout_secs** (default 300): Connections idle for this duration are closed. Applies to HTTP/1.1 keep-alive connections.

```toml
[proxy]
listen = "127.0.0.1:3128"
max_connections = 500
idle_timeout_secs = 120
```

## Logging and Auditing

Alice logs all policy decisions as structured JSON:
- Allowed requests: host, path, method, rule index
- Denied requests: host, path (if inspected), rule index or "default deny"
- Connection errors: upstream TLS failures, timeouts, etc.

Sensitive data (request/response bodies, headers) is NOT logged by default.

## Credential Injection Security

Alice can inject real credentials into outbound requests, replacing dummy tokens that Bob sends. This section analyzes the security properties of credential storage.

### Credential Sources

| Source | Config | Secret Location |
|--------|--------|-----------------|
| Environment | `env = "VAR"` | Process environment |
| File | `file = "/path"` | Filesystem |
| SOPS | `sops_credentials = [...]` | Encrypted file, decrypted at startup |

### Local Attacker (Eve) Threat Model

Eve is a process running on the same system as Alice, potentially as a different user.

**What Eve can see (all sources):**
- Main config file: credential names, host patterns, header names, dummy token values
- That credentials exist for certain hosts (observable from config)

**Environment-based credentials (`env =`):**

| Attack Vector | Eve's Access |
|--------------|--------------|
| `/proc/<pid>/environ` | Requires same user or root |
| Shell history / process listing | May leak var names, not values |
| Config file | Shows which env vars contain secrets |

Risk: Medium. Environment variables are readable by same-user processes. Container isolation or separate users mitigate this.

**File-based credentials (`file =`):**

| Attack Vector | Eve's Access |
|--------------|--------------|
| Direct file read | Depends on file permissions |
| Config file | Reveals file paths |
| LFI in other services | Could expose secret files |

Risk: Medium. Depends entirely on filesystem permissions. Use restrictive permissions (0400) and consider tmpfs or secrets managers.

**SOPS-based credentials (`sops_credentials`):**

| Attack Vector | Eve's Access |
|--------------|--------------|
| SOPS file on disk | Encrypted, unreadable without keys |
| Config file | Reveals SOPS file paths, not secrets |
| LFI in other services | Only exposes encrypted data |
| Environment variables | Secret not present |
| Decryption keys (age/GPG/KMS) | Requires same access Alice has |
| Memory dump of Alice | Requires ptrace or same user |

Risk: Low. SOPS credentials are the most secure option:
- **No LFI risk**: Secrets are never written to disk in plaintext
- **No environment leak risk**: Secrets are not in environment variables
- **Encryption at rest**: SOPS files are encrypted; Eve needs decryption capability
- **Key-based access control**: KMS/age/GPG keys determine who can decrypt

To extract SOPS secrets, Eve must either:
1. Dump Alice's process memory (requires `CAP_SYS_PTRACE` or same UID)
2. Have access to the same decryption keys (age key file, GPG keyring, KMS permissions)

### Defense in Depth: Proxy Authentication

Credential extraction and credential *usage through Alice* are separate concerns:

**Extraction** (getting the secret):
- Memory dump still works regardless of credential source
- SOPS only protects at-rest (no LFI, no env leak) - not in-memory

**Usage through Alice** (exploiting the secret via the proxy):
- Requires Bob's proxy auth credentials
- Eve cannot connect to Alice and trigger credential injection without authenticating as Bob
- Even knowing the dummy token pattern, Eve gets 407 without proxy auth

If Eve extracts credentials from memory, they can only use them by connecting directly to upstream (bypassing Alice). At that point Alice's policy controls don't apply, but:
- Eve already has arbitrary network access (they're on the system)
- The credential was protected from Bob, not from privileged local processes

### Recommendations

For high-security deployments:
1. **Enable proxy auth** - Eve can't use Alice without Bob's credentials
2. **Use SOPS** with KMS or age keys that Eve cannot access
3. **Run Alice as dedicated user** that Eve cannot ptrace
4. **Disable ptrace** via `kernel.yama.ptrace_scope=2` or seccomp

For convenience (development/testing):
- Environment variables are acceptable when Eve is not a concern
- File-based secrets work well with container secrets or tmpfs mounts

## Operational Security

### Running Alice

- Run as unprivileged user (no root required)
- Bind to localhost if Bob is local; use firewall rules for remote access
- Rotate CA regularly by restarting Alice
- Monitor logs for unexpected denied requests (policy gaps or attacks)

### Network Isolation

Alice is most effective when combined with:
- Network namespaces (Linux)
- Firewall rules blocking direct internet access
- Container networking that forces traffic through the proxy

Without network-level enforcement, Bob can bypass Alice entirely.
