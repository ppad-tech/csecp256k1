{
  description = "haskell-secp256k1";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
        {
          devShells.default = pkgs.mkShell {
            buildInputs = [
              pkgs.secp256k1
              pkgs.haskell.compiler.ghc964
              pkgs.haskell.packages.ghc964.cabal-install
            ];

            shellHook = ''
              echo "entering shell.."
              PS1="\e[1;34m[nix] \w$ \e[0m"
              echo "$(${pkgs.haskell.compiler.ghc964}/bin/ghc --version)"
            '';
          };
        }
      );
}
