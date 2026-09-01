//! Generated gRPC bindings for the sanctum credential broker.
//!
//! The crate exists so `proto/sanctum.proto` and its `tonic-build` codegen
//! live in exactly one place. Before it, the schema and an identical
//! `build.rs` were copied into the broker and every consumer, kept in sync
//! by a comment at the top of the file — which had already gone stale.
//! Consumers now take a cargo path dep instead:
//!
//! ```toml
//! sanctum-client = { path = "../sanctum-client" }
//! ```
//!
//! Both halves of the service are generated: consumers use
//! [`SanctumClient`], the broker (and tests that stand up a fake broker)
//! use [`Sanctum`] / [`SanctumServer`].
//!
//! Nothing above the wire schema belongs here. Socket and state-dir
//! defaults stay in `sanctum::client`, which consumers can depend on
//! separately.

/// Raw generated module, matching the proto package name (`sanctum`).
///
/// Prefer the re-exports at the crate root; reach in here for the
/// `sanctum_client` / `sanctum_server` modules' other items (interceptors,
/// codec config) when you need them.
pub mod proto {
    tonic::include_proto!("sanctum");
}

pub use proto::sanctum_client::SanctumClient;
pub use proto::sanctum_server::{Sanctum, SanctumServer};
pub use proto::{
    AccessToken, ForceRefreshRequest, GetAccessTokenRequest, ImportCredentialRequest,
    ImportCredentialResponse,
};
