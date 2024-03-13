# csecp256k1

Bindings to bitcoin-core/secp256k1, which provides digital signatures
and other cryptographic primitives on the secp256k1 elliptic curve.

This library exposes a minimal subset of the underlying library, mainly
supporting ECDSA/Schnorr signatures and ECDH secret computation, as well
as utilities for public key manipulation.

## Documentation

API documentation and examples are hosted at
[docs.ppad.tech/csecp256k1][hadoc].

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled. Enter a
development shell with:

```
$ nix develop
```

Then do e.g.:

```
$ cabal repl ppad-csecp256k1
```

to get a REPL for the main library, or:

```
$ cabal repl secp256k1-sys-tests
```

to get one for the internal test suite. You can run all tests via:

```
$ cabal test
```

and the benchmarks via:

```
$ cabal bench
```

## Security

These bindings aim at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be challenging to achieve.

If you discover any vulnerabilities, please disclose them via
security@ppad.tech.

## Attribution

This implementation has benefited greatly and uses modified versions of
code from both [secp256k1-haskell][hsecp] (test cases, FFI/bytestring
manipulation) and [rust-secp256k1][rsecp] (dependency vendoring).

[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/csecp256k1
[hsecp]: https://github.com/haskoin/secp256k1-haskell
[rsecp]: https://github.com/rust-bitcoin/rust-secp256k1
