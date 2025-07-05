{ inputs, ... }:
{
  imports = [
    inputs.rust-flake.flakeModules.default
    inputs.rust-flake.flakeModules.nixpkgs
    inputs.process-compose-flake.flakeModule
    inputs.cargo-doc-live.flakeModule
  ];
  perSystem = { config, self', pkgs, lib, ... }: {
    rust-project.crates."anthropic-proxy".crane.args = {
      buildInputs = lib.optionals pkgs.stdenv.isDarwin (
        with pkgs.darwin.apple_sdk.frameworks; [
          IOKit
        ]
      );
    };
    packages.default = self'.packages.anthropic-proxy;
  };
}
