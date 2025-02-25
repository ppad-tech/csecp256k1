/***********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_IMPL_H
#define SECP256K1_ECMULT_GEN_IMPL_H

#include "util.h"
#include "scalar.h"
#include "group.h"
#include "ecmult_gen.h"
#include "hash_impl.h"
#include "precomputed_ecmult_gen.h"

static void haskellsecp256k1_v0_1_0_ecmult_gen_context_build(haskellsecp256k1_v0_1_0_ecmult_gen_context *ctx) {
    haskellsecp256k1_v0_1_0_ecmult_gen_blind(ctx, NULL);
    ctx->built = 1;
}

static int haskellsecp256k1_v0_1_0_ecmult_gen_context_is_built(const haskellsecp256k1_v0_1_0_ecmult_gen_context* ctx) {
    return ctx->built;
}

static void haskellsecp256k1_v0_1_0_ecmult_gen_context_clear(haskellsecp256k1_v0_1_0_ecmult_gen_context *ctx) {
    ctx->built = 0;
    haskellsecp256k1_v0_1_0_scalar_clear(&ctx->blind);
    haskellsecp256k1_v0_1_0_gej_clear(&ctx->initial);
}

/* For accelerating the computation of a*G:
 * To harden against timing attacks, use the following mechanism:
 * * Break up the multiplicand into groups of PREC_BITS bits, called n_0, n_1, n_2, ..., n_(PREC_N-1).
 * * Compute sum(n_i * (PREC_G)^i * G + U_i, i=0 ... PREC_N-1), where:
 *   * U_i = U * 2^i, for i=0 ... PREC_N-2
 *   * U_i = U * (1-2^(PREC_N-1)), for i=PREC_N-1
 *   where U is a point with no known corresponding scalar. Note that sum(U_i, i=0 ... PREC_N-1) = 0.
 * For each i, and each of the PREC_G possible values of n_i, (n_i * (PREC_G)^i * G + U_i) is
 * precomputed (call it prec(i, n_i)). The formula now becomes sum(prec(i, n_i), i=0 ... PREC_N-1).
 * None of the resulting prec group elements have a known scalar, and neither do any of
 * the intermediate sums while computing a*G.
 * The prec values are stored in haskellsecp256k1_v0_1_0_ecmult_gen_prec_table[i][n_i] = n_i * (PREC_G)^i * G + U_i.
 */
static void haskellsecp256k1_v0_1_0_ecmult_gen(const haskellsecp256k1_v0_1_0_ecmult_gen_context *ctx, haskellsecp256k1_v0_1_0_gej *r, const haskellsecp256k1_v0_1_0_scalar *gn) {
    int bits = ECMULT_GEN_PREC_BITS;
    int g = ECMULT_GEN_PREC_G(bits);
    int n = ECMULT_GEN_PREC_N(bits);

    haskellsecp256k1_v0_1_0_ge add;
    haskellsecp256k1_v0_1_0_ge_storage adds;
    haskellsecp256k1_v0_1_0_scalar gnb;
    int i, j, n_i;
    
    memset(&adds, 0, sizeof(adds));
    *r = ctx->initial;
    /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
    haskellsecp256k1_v0_1_0_scalar_add(&gnb, gn, &ctx->blind);
    add.infinity = 0;
    for (i = 0; i < n; i++) {
        n_i = haskellsecp256k1_v0_1_0_scalar_get_bits(&gnb, i * bits, bits);
        for (j = 0; j < g; j++) {
            /** This uses a conditional move to avoid any secret data in array indexes.
             *   _Any_ use of secret indexes has been demonstrated to result in timing
             *   sidechannels, even when the cache-line access patterns are uniform.
             *  See also:
             *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
             *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
             *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
             *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
             *    (https://www.tau.ac.il/~tromer/papers/cache.pdf)
             */
            haskellsecp256k1_v0_1_0_ge_storage_cmov(&adds, &haskellsecp256k1_v0_1_0_ecmult_gen_prec_table[i][j], j == n_i);
        }
        haskellsecp256k1_v0_1_0_ge_from_storage(&add, &adds);
        haskellsecp256k1_v0_1_0_gej_add_ge(r, r, &add);
    }
    n_i = 0;
    haskellsecp256k1_v0_1_0_ge_clear(&add);
    haskellsecp256k1_v0_1_0_scalar_clear(&gnb);
}

/* Setup blinding values for haskellsecp256k1_v0_1_0_ecmult_gen. */
static void haskellsecp256k1_v0_1_0_ecmult_gen_blind(haskellsecp256k1_v0_1_0_ecmult_gen_context *ctx, const unsigned char *seed32) {
    haskellsecp256k1_v0_1_0_scalar b;
    haskellsecp256k1_v0_1_0_gej gb;
    haskellsecp256k1_v0_1_0_fe s;
    unsigned char nonce32[32];
    haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256 rng;
    unsigned char keydata[64];
    if (seed32 == NULL) {
        /* When seed is NULL, reset the initial point and blinding value. */
        haskellsecp256k1_v0_1_0_gej_set_ge(&ctx->initial, &haskellsecp256k1_v0_1_0_ge_const_g);
        haskellsecp256k1_v0_1_0_gej_neg(&ctx->initial, &ctx->initial);
        haskellsecp256k1_v0_1_0_scalar_set_int(&ctx->blind, 1);
        return;
    }
    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    haskellsecp256k1_v0_1_0_scalar_get_b32(keydata, &ctx->blind);
    /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
     *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
     *   asking the caller for blinding values directly and expecting them to retry on failure.
     */
    VERIFY_CHECK(seed32 != NULL);
    memcpy(keydata + 32, seed32, 32);
    haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256_initialize(&rng, keydata, 64);
    memset(keydata, 0, sizeof(keydata));
    haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
    haskellsecp256k1_v0_1_0_fe_set_b32_mod(&s, nonce32);
    haskellsecp256k1_v0_1_0_fe_cmov(&s, &haskellsecp256k1_v0_1_0_fe_one, haskellsecp256k1_v0_1_0_fe_normalizes_to_zero(&s));
    /* Randomize the projection to defend against multiplier sidechannels.
       Do this before our own call to haskellsecp256k1_v0_1_0_ecmult_gen below. */
    haskellsecp256k1_v0_1_0_gej_rescale(&ctx->initial, &s);
    haskellsecp256k1_v0_1_0_fe_clear(&s);
    haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
    haskellsecp256k1_v0_1_0_scalar_set_b32(&b, nonce32, NULL);
    /* A blinding value of 0 works, but would undermine the projection hardening. */
    haskellsecp256k1_v0_1_0_scalar_cmov(&b, &haskellsecp256k1_v0_1_0_scalar_one, haskellsecp256k1_v0_1_0_scalar_is_zero(&b));
    haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256_finalize(&rng);
    memset(nonce32, 0, 32);
    /* The random projection in ctx->initial ensures that gb will have a random projection. */
    haskellsecp256k1_v0_1_0_ecmult_gen(ctx, &gb, &b);
    haskellsecp256k1_v0_1_0_scalar_negate(&b, &b);
    ctx->blind = b;
    ctx->initial = gb;
    haskellsecp256k1_v0_1_0_scalar_clear(&b);
    haskellsecp256k1_v0_1_0_gej_clear(&gb);
}

#endif /* SECP256K1_ECMULT_GEN_IMPL_H */
