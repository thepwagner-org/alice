# vendor/

Crates in here are **not** third-party dependencies.

They are internal crates from the monorepo this repository is mirrored out of.
The mirror ships one project per repository, so a crate that the primary crate
reaches via a `path = "../<name>"` dependency has no home here — it gets copied
in at sync time instead, and the root `Cargo.toml` is rewritten to point at
`vendor/<name>`.

Everything under this directory is generated. Edits made here are overwritten
by the next sync, so please open issues against the primary crate rather than
pull requests against `vendor/`.
