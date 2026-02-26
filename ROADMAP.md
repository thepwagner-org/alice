# Roadmap

## Future Possibilities

- **Response inspection** - Inspect and modify upstream responses (e.g., token redaction)
- **LLM usage parsing** - Additional providers (OpenAI, Google, etc.)
- **IPv6 support** (currently IPv4 only)
- **WebSocket inspection**
- **Rate limiting** per host or credential
- **Connection pooling tuning**
- **AWS credential re-signing** - Proxy-side SigV4 signing for AWS APIs (analogous to GCP JWT re-signing)

## Non-Goals

Explicitly out of scope to keep the project focused:
- **Plain HTTP support** - HTTPS only
- **Per-client proxy isolation** - single shared proxy
- **Regex patterns for rules** - globs only
