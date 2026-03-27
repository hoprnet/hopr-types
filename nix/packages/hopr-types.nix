# contracts.nix - HOPR contracts Rust package definitions
#
# Builds the hopr-types crate for multiple platforms using nix-lib builders.
# Source filtering, rev, and build arguments are all defined here.
# The contracts-specific preConfigure generates foundry.toml from foundry.in.toml
# (only for the main build; the deps-only build does not need it).

{
  builders,
  nixLib,
  self,
  lib
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
    # Extra files not covered by the default .rs/.toml extensions
    # extraFiles = [
    #   (root + "/ethereum/bindings/contracts-addresses.json")
    #   (root + "/ethereum/contracts/remappings.txt")
    #   (fs.fileFilter (file: file.hasExt "sol") (root + "/vendor/solidity"))
    #   (fs.fileFilter (file: file.hasExt "sol") (root + "/ethereum/contracts/src"))
    # ];
  };

  cargoToml = ../../Cargo.toml;

  buildArgs = {
    inherit
      src
      depsSrc
      rev
      cargoToml
      ;
  };

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


  clippy = buildLib builders.local { runClippy = true; };

  test = buildLib builders.local { runTests = true; };

  docs = buildLib builders.localNightly { buildDocs = true; };

  # Cross-compiled rlib packages
  # Artifacts are available at: ./result/lib/libhopr_bindings.rlib
  lib-hopr-types-x86_64-linux = buildLib builders."x86_64-linux" { };
  lib-hopr-types-aarch64-linux = buildLib builders."aarch64-linux" { };
  lib-hopr-types-x86_64-darwin = buildLib builders."x86_64-darwin" { };
  lib-hopr-types-aarch64-darwin = buildLib builders."aarch64-darwin" { };
  lib-hopr-types = buildLib builders.local { };

}
