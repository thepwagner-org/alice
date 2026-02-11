{pkgs, ...}:
pkgs.mkShell {
  buildInputs = with pkgs; [
    cargo
    rustfmt
    clippy
    rust-analyzer

    pkg-config
    openssl.dev
  ];
}
