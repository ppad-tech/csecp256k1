{
  description = "secp256k1-sys";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs  = nixpkgs.legacyPackages.${system};
        hpkgs = pkgs.haskell.packages.ghc964;
        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;

        lib = "secp256k1-sys";
      in
        {
          packages.${lib} = hpkgs.callCabal2nix lib self rec { };

          defaultPackage = self.packages.${system}.${lib};

          devShells.default = pkgs.mkShell {
            buildInputs = [
              cabal
            ];

            inputsFrom = builtins.attrValues self.packages.${system};

            shellHook = ''
              PS1="[nix] \w$ "
              echo "entering shell, using"
              echo "ghc:   $(${ghc}/bin/ghc --version)"
              echo "cabal: $(${cabal}/bin/cabal --version)"
            '';
          };
        }
      );
}

