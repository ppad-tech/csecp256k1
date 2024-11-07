# ppad-csecp256k1

Bindings to bitcoin-core/secp256k1, which provides digital signatures
and other cryptographic primitives on the secp256k1 elliptic curve.

This library exposes a minimal subset of the underlying library, mainly
supporting ECDSA/Schnorr signatures and ECDH secret computation, as well
as utilities for public key manipulation.

## Documentation

API documentation and examples are hosted at
[docs.ppad.tech/csecp256k1][hadoc].

## Performance

As we bind to libsecp256k1, the resulting functions are very fast:

```
  benchmarking csecp256k1/ecdsa/sign
  time                 33.67 μs   (33.43 μs .. 34.00 μs)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 33.74 μs   (33.64 μs .. 33.87 μs)
  std dev              378.5 ns   (259.2 ns .. 606.8 ns)

  benchmarking csecp256k1/ecdsa/verify
  time                 38.01 μs   (37.44 μs .. 38.65 μs)
                       0.999 R²   (0.998 R² .. 1.000 R²)
  mean                 37.82 μs   (37.56 μs .. 38.16 μs)
  std dev              912.8 ns   (657.5 ns .. 1.263 μs)
  variance introduced by outliers: 22% (moderately inflated)

  benchmarking csecp256k1/schnorr/sign
  time                 49.97 μs   (49.60 μs .. 50.41 μs)
                       0.999 R²   (0.999 R² .. 1.000 R²)
  mean                 49.95 μs   (49.54 μs .. 50.54 μs)
  std dev              1.618 μs   (1.200 μs .. 2.399 μs)
  variance introduced by outliers: 34% (moderately inflated)

  benchmarking csecp256k1/schnorr/verify
  time                 41.84 μs   (41.32 μs .. 42.26 μs)
                       0.999 R²   (0.998 R² .. 0.999 R²)
  mean                 41.50 μs   (41.06 μs .. 41.94 μs)
  std dev              1.432 μs   (1.167 μs .. 1.715 μs)
  variance introduced by outliers: 37% (moderately inflated)

  benchmarking csecp256k1/ecdh/ecdh
  time                 47.43 μs   (46.78 μs .. 48.19 μs)
                       0.998 R²   (0.997 R² .. 0.999 R²)
  mean                 46.86 μs   (46.33 μs .. 47.58 μs)
  std dev              2.075 μs   (1.609 μs .. 2.747 μs)
  variance introduced by outliers: 49% (moderately inflated)
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

[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/csecp256k1
[hsecp]: https://github.com/haskoin/secp256k1-haskell
[rsecp]: https://github.com/rust-bitcoin/rust-secp256k1
[ut340]: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
[wyche]: https://github.com/C2SP/wycheproof
