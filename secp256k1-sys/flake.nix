{
  description = "secp256k1-sys";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "secp256k1-sys";

        config = {
          packageOverrides = super: let self = super.pkgs; in rec {
            haskell = super.haskell // {
              packageOverrides = self: super: {
                ${lib} = super.callCabal2nix lib ./. {};
              };
            };
          };
        };

        pkgs  = import nixpkgs { inherit system; inherit config; };
        hpkgs = pkgs.haskell.packages.ghc964;

        cc    = pkgs.stdenv.cc;
        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;
      in
        {
          packages.${lib} = hpkgs.callCabal2nix lib self rec { };

          defaultPackage = self.packages.${system}.${lib};

          devShells.default = hpkgs.shellFor {
            packages = p: [
              p.${lib}
            ];

            buildInputs = [
              cabal
              cc
            ];

            inputsFrom = builtins.attrValues self.packages.${system};

            shellHook = ''
              PS1="[${lib}] \w$ "
              echo "entering ${system} shell, using"
              echo "cc:    $(${cc}/bin/cc --version)"
              echo "ghc:   $(${ghc}/bin/ghc --version)"
              echo "cabal: $(${cabal}/bin/cabal --version)"
            '';
          };
        }
      );
}

