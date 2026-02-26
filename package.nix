{
  pkgs,
  buildRustPackage,
  ...
}:
buildRustPackage {
  src = ./.;
  extraArgs = {
    doCheck = false;

    meta = with pkgs.lib; {
      description = "A sanitizing HTTPS proxy for controlled network access";
      license = licenses.mit;
      platforms = platforms.linux;
    };
  };
}
