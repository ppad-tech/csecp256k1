{
  description = "ppad-csecp256k1";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-csecp256k1";
        sys = "secp256k1-sys";

        config = {
          packageOverrides = super: let self = super.pkgs; in rec {
            haskell = super.haskell // {
              packageOverrides = self: super: {
                ${sys} = super.callCabal2nix sys ./${sys} {};
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
          packages.${lib} = hpkgs.${lib};

          defaultPackage = self.packages.${system}.${lib};

          devShells.default = hpkgs.shellFor {
            packages = p: [
              p.${lib} p.${sys}
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

