fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/sanctum.proto");

    tonic_prost_build::configure()
        // Suppress unused_results in generated code (tonic does opaque
        // header/extension inserts).
        .server_mod_attribute(".", "#[allow(unused_results)]")
        .client_mod_attribute(".", "#[allow(unused_results)]")
        // tonic mixes outer doc comments with inner allow attributes.
        .server_mod_attribute(".", "#[allow(clippy::mixed_attributes_style)]")
        .client_mod_attribute(".", "#[allow(clippy::mixed_attributes_style)]")
        .compile_protos(&["proto/sanctum.proto"], &["proto"])?;

    Ok(())
}
