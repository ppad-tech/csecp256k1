# ppad-csecp256k1

![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-csecp256k1-lightblue)](https://docs.ppad.tech/csecp256k1)

Bindings to bitcoin-core/secp256k1, which provides digital signatures
and other cryptographic primitives on the secp256k1 elliptic curve.

This library exposes a minimal subset of the underlying library, mainly
supporting ECDSA/Schnorr signatures and ECDH secret computation, as well
as utilities for public key manipulation.

For a pure Haskell secp256k1 implementation, see [ppad-secp256k1][ppads].

## Documentation

API documentation and examples are hosted at
[docs.ppad.tech/csecp256k1][hadoc].

## Performance

As we bind to libsecp256k1, the resulting functions are very fast:

```
  benchmarking csecp256k1/ecdsa/sign
  time                 13.31 μs   (13.30 μs .. 13.31 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 13.33 μs   (13.32 μs .. 13.33 μs)
  std dev              11.15 ns   (8.932 ns .. 15.01 ns)

  benchmarking csecp256k1/ecdsa/verify
  time                 12.35 μs   (12.34 μs .. 12.38 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 12.35 μs   (12.35 μs .. 12.36 μs)
  std dev              21.83 ns   (9.273 ns .. 47.76 ns)

  benchmarking csecp256k1/schnorr/sign
  time                 18.35 μs   (18.35 μs .. 18.36 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 18.35 μs   (18.35 μs .. 18.35 μs)
  std dev              5.990 ns   (4.283 ns .. 9.131 ns)

  benchmarking csecp256k1/schnorr/verify
  time                 14.15 μs   (14.14 μs .. 14.15 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 14.14 μs   (14.13 μs .. 14.15 μs)
  std dev              30.51 ns   (14.54 ns .. 57.66 ns)

  benchmarking csecp256k1/ecdh/ecdh
  time                 15.02 μs   (15.02 μs .. 15.03 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 15.02 μs   (15.00 μs .. 15.03 μs)
  std dev              34.78 ns   (10.81 ns .. 71.53 ns)
```

## Security

These bindings aim at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be challenging to achieve.

The Schnorr implementation within has been tested against the [official
BIP0340 vectors][ut340] (sans those using arbitrary-size messages, which
we're not at present supporting), and ECDSA has been tested against the
relevant [Wycheproof vectors][wyche].

If you discover any vulnerabilities, please disclose them via
security@ppad.tech.

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

## Attribution

This implementation has benefited greatly and uses modified versions of
code from both [secp256k1-haskell][hsecp] (test cases, FFI/bytestring
manipulation) and [rust-secp256k1][rsecp] (dependency vendoring).

[ppads]: https://github.com/ppad-tech/secp256k1
[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/csecp256k1
[hsecp]: https://github.com/haskoin/secp256k1-haskell
[rsecp]: https://github.com/rust-bitcoin/rust-secp256k1
[ut340]: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
[wyche]: https://github.com/C2SP/wycheproof
