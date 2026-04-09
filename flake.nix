{
  description = "HOPR types";

  inputs = {
    # Core Nix ecosystem dependencies
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/release-25.11";
    flake-utils.url = "github:numtide/flake-utils";

    # HOPR Nix Library (provides flake-utils and reusable build functions)
    nix-lib.url = "github:hoprnet/nix-lib/v1.1.0";

    # Rust build system
    crane.url = "github:ipetkov/crane";
    rust-overlay.url = "github:oxalica/rust-overlay";

    # Development tools and quality assurance
    pre-commit.url = "github:cachix/git-hooks.nix";
    flake-root.url = "github:srid/flake-root";
    treefmt-nix.url = "github:numtide/treefmt-nix";

    # Input dependency optimization
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    nix-lib.inputs.nixpkgs.follows = "nixpkgs";
    nix-lib.inputs.crane.follows = "crane";
    nix-lib.inputs.rust-overlay.follows = "rust-overlay";
    nix-lib.inputs.flake-utils.follows = "flake-utils";
    pre-commit.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      nix-lib,
      flake-parts,
      rust-overlay,
      pre-commit,
      ...
    }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.treefmt-nix.flakeModule
        inputs.flake-root.flakeModule
      ];
      perSystem =
        {
          config,
          lib,
          system,
          ...
        }:
        let
          localSystem = system;
          overlays = [
            (import rust-overlay)
          ];
          pkgs = import nixpkgs { inherit localSystem overlays; };

          # Platform information
          buildPlatform = pkgs.stdenv.buildPlatform;

          sharedExcludes = [ ".gcloudignore" ];

          # Import nix-lib for this system
          nixLib = nix-lib.lib.${system};

          # Create all Rust builders for cross-compilation using nix-lib
          builders = nixLib.mkRustBuilders {
            inherit localSystem;
            rustToolchainFile = ./rust-toolchain.toml;
          };

          # Import all HOPR types packages (uses nix-lib builders + mkRustPackage).
          # src, depsSrc, and rev are computed internally in hopr-types.nix.
          hoprTypesPackages = import ./nix/packages/hopr-types.nix {
            inherit
              builders
              nixLib
              self
              lib
              ;
          };

          # Linux packages for Docker image contents (always x86_64-linux for
          # server deployment; this lets the image be built on Darwin too)
          pkgsLinux = import nixpkgs {
            system = "x86_64-linux";
            inherit overlays;
          };

          pre-commit-check = pre-commit.lib.${system}.run {
            src = ./.;
            hooks = {
              # https://github.com/cachix/git-hooks.nix
              treefmt.enable = false;
              treefmt.package = config.treefmt.build.wrapper;
              check-executables-have-shebangs.enable = true;
              check-shebang-scripts-are-executable.enable = true;
              check-case-conflicts.enable = true;
              check-symlinks.enable = true;
              check-merge-conflicts.enable = true;
              check-added-large-files.enable = true;
              commitizen.enable = true;
            };
            tools = pkgs;
            excludes = sharedExcludes ++ [
              "vendor/"
              "ethereum/contracts/"
              "ethereum/bindings/src/codegen"
            ];
          };

          # Rust toolchains
          stableToolchain =
            (pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override
              {
                targets = [
                  (
                    if buildPlatform.config == "arm64-apple-darwin" then
                      "aarch64-apple-darwin"
                    else
                      buildPlatform.config
                  )
                ];
              };

          shellArgs = {
            treefmtWrapper = config.treefmt.build.wrapper;
            treefmtPrograms = pkgs.lib.attrValues config.treefmt.build.programs;
            shellHook = ''
              echo "Running pre-commit checks..."
              ${pre-commit-check.shellHook}
            '';
            extraPackages = with pkgs; [
              cargo-nextest
              sqlite
              yq-go
            ];
          };

          shells = {
            default = nixLib.mkDevShell (
              {
                rustToolchain = stableToolchain;
                shellName = "Development";
              }
              // shellArgs
            );
            coverage = nixLib.mkDevShell {
              rustToolchainFile = ./rust-toolchain.toml;
              shellName = "Coverage";
              withLlvmTools = true;
              extraPackages = with pkgs; [ cargo-nextest ];
            };
            ci = pkgs.mkShell {
              packages = [ pkgs.zizmor ];
            };
          };
        in
        {
          treefmt = {
            inherit (config.flake-root) projectRootFile;

            settings.global.excludes = sharedExcludes ++ [
              "**/*.id"
              "**/.cargo-ok"
              "**/.gitignore"
              ".actrc"
              ".dockerignore"
              ".editorconfig"
              ".gitattributes"
              ".yamlfmt"
              "LICENSE"
              "Makefile"
              ".github/workflows/build-binaries.yaml"
              "docs/*"
              "target/*"
              "vendor/*"
            ];

            programs.shfmt.enable = true;
            settings.formatter.shfmt.includes = [
              "*.sh"
            ];

            programs.yamlfmt.enable = true;
            settings.formatter.yamlfmt.includes = [
              ".github/labeler.yml"
              ".github/workflows/*.yaml"
            ];
            # trying setting from https://github.com/google/yamlfmt/blob/main/docs/config-file.md
            settings.formatter.yamlfmt.settings = {
              formatter.type = "basic";
              formatter.max_line_length = 120;
              formatter.trim_trailing_whitespace = true;
              formatter.scan_folded_as_literal = true;
              formatter.include_document_start = true;
            };

            programs.prettier.enable = true;
            settings.formatter.prettier.includes = [
              "*.md"
              "*.json"
            ];
            settings.formatter.prettier.excludes = [
              "*.yml"
              "*.yaml"
            ];
            programs.rustfmt.enable = true;
            # using the official Nixpkgs formatting
            # see https://github.com/NixOS/rfcs/blob/master/rfcs/0166-nix-formatting.md
            programs.nixfmt.enable = true;
            programs.taplo.enable = true;
            programs.ruff-format.enable = true;

            settings.formatter.rustfmt = {
              command = "${pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default)}/bin/rustfmt";
            };
          };

          checks = {
            inherit (hoprTypesPackages) clippy;
            inherit pre-commit-check;
          };

          apps = {
            update-github-labels = nixLib.mkUpdateGithubLabelsApp // {
              meta.description = "Update GitHub labels from repository configuration";
            };
            check = (nixLib.mkCheckApp { inherit system; }) // {
              meta.description = "Run all CI checks for the current system";
            };
            audit = (nixLib.mkAuditApp { rustToolchainFile = ./rust-toolchain.toml; }) // {
              meta.description = "Run cargo audit to check for security vulnerabilities";
            };
            coverage-unit = {
              type = "app";
              program = toString (
                pkgs.writeShellScript "coverage-unit" ''
                  nix develop .#coverage -c cargo llvm-cov nextest --workspace --features all-types,fixed-rng,use-bindings,serde --lib --lcov --output-path coverage.lcov
                ''
              );
              meta.description = "Generate unit test coverage report (coverage.lcov)";
            };
          };

          packages = {
            inherit (hoprTypesPackages) test lib-hopr-types;
          }
          // lib.optionalAttrs pkgs.stdenv.isLinux {
            inherit (hoprTypesPackages) lib-hopr-types-x86_64-linux lib-hopr-types-aarch64-linux;
          }
          // lib.optionalAttrs pkgs.stdenv.isDarwin {
            inherit (hoprTypesPackages) lib-hopr-types-x86_64-darwin lib-hopr-types-aarch64-darwin;
          }
          // {
            inherit pre-commit-check;
            default = hoprTypesPackages.lib-hopr-types;
          };

          devShells = shells;

          formatter = config.treefmt.build.wrapper;
        };
      # platforms which are supported as build environments
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
    };
}
