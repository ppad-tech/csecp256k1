{
  description = "haskell-secp256k1";

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
      in
        {
          devShells.default = pkgs.mkShell {
            buildInputs = [
              cabal
            ];

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
