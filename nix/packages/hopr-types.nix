# hopr-types.nix - HOPR types Rust package definitions
#
# Builds the hopr-types crate for multiple platforms using nix-lib builders.
# Source filtering, rev, and build arguments are all defined here.

{
  builders,
  nixLib,
  self,
  lib,
}:
let
  fs = lib.fileset;
  root = ./../..;

  rev = toString (self.shortRev or self.dirtyShortRev);

  depsSrc = nixLib.mkDepsSrc {
    inherit root fs;
  };

  src = nixLib.mkSrc {
    inherit root fs;
    extraExtensions = [ "snap" ];
  };

  cargoToml = ../../Cargo.toml;

  buildLib =
    builder: args:
    builder.callPackage nixLib.mkRustLibrary (
      {
        inherit
          src
          depsSrc
          cargoToml
          rev
          ;
      }
      // args
    );
in
{

  clippy = buildLib builders.local {
    runClippy = true;
    cargoExtraArgs = "--features all-types,use-bindings,serde";
  };

  test = buildLib builders.local {
    runTests = true;
    cargoExtraArgs = "--features all-types,fixed-rng,use-bindings,serde";
  };

  # Cross-compiled rlib packages
  # Artifacts are available at: ./result/lib/libhopr_types.rlib
  lib-hopr-types-x86_64-linux = buildLib builders."x86_64-linux" { };
  lib-hopr-types-aarch64-linux = buildLib builders."aarch64-linux" { };
  lib-hopr-types-x86_64-darwin = buildLib builders."x86_64-darwin" { };
  lib-hopr-types-aarch64-darwin = buildLib builders."aarch64-darwin" { };
  lib-hopr-types = buildLib builders.local { };

}
