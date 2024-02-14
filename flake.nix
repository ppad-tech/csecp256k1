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
        ghc   = pkgs.haskell.compiler.ghc964;
        cabal = pkgs.haskell.packages.ghc964.cabal-install;
        hspec = pkgs.haskell.packages.ghc964.hspec;
      in
        {
          devShells.default = pkgs.mkShell {
            buildInputs = [
              ghc
              cabal
              hspec
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
