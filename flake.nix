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

        pkgs = import nixpkgs { inherit system; };
        hlib = pkgs.haskell.lib;

        hpkgs = pkgs.haskell.packages.ghc964.override {
          overrides = new: old: {
            ${lib} = old.callCabal2nix lib ./. {};
          };
        };

        cc    = pkgs.stdenv.cc;
        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;
      in
        {
          # cabal2nix disables haddock for packages with internal
          # dependencies like secp256k1-sys, so enable it manually
          packages.${lib} = hlib.doHaddock hpkgs.${lib};

          defaultPackage = self.packages.${system}.${lib};

          hpkgs = hpkgs;

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

