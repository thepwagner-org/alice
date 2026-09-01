# sanctum-client

Generated gRPC bindings for the sanctum credential broker. Owns
`proto/sanctum.proto` and the `tonic-build` codegen that turns it into
Rust, shared via a cargo path dep.

```toml
sanctum-client = { path = "../sanctum-client" }
```

```rust
use sanctum_client::{GetAccessTokenRequest, SanctumClient};
```

Both halves of the service are generated — consumers use `SanctumClient`,
the broker and tests that stand up a fake broker use `Sanctum` /
`SanctumServer`.

There is exactly one copy of `sanctum.proto` in the tree, and it is the one
in this crate. Adding a second is how the schema drifts.

Socket and state-dir defaults are not here; they live in `sanctum::client`,
which is a separate dep.
