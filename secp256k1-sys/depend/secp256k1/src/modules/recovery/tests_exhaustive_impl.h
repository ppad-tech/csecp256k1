/***********************************************************************
 * Copyright (c) 2016 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_RECOVERY_EXHAUSTIVE_TESTS_H
#define SECP256K1_MODULE_RECOVERY_EXHAUSTIVE_TESTS_H

#include "main_impl.h"
#include "../../../include/secp256k1_recovery.h"

static void test_exhaustive_recovery_sign(const haskellsecp256k1_v0_1_0_context *ctx, const haskellsecp256k1_v0_1_0_ge *group) {
    int i, j, k;
    uint64_t iter = 0;

    /* Loop */
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; i++) {  /* message */
        for (j = 1; j < EXHAUSTIVE_TEST_ORDER; j++) {  /* key */
            if (skip_section(&iter)) continue;
            for (k = 1; k < EXHAUSTIVE_TEST_ORDER; k++) {  /* nonce */
                const int starting_k = k;
                haskellsecp256k1_v0_1_0_fe r_dot_y_normalized;
                haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature rsig;
                haskellsecp256k1_v0_1_0_ecdsa_signature sig;
                haskellsecp256k1_v0_1_0_scalar sk, msg, r, s, expected_r;
                unsigned char sk32[32], msg32[32];
                int expected_recid;
                int recid;
                int overflow;
                haskellsecp256k1_v0_1_0_scalar_set_int(&msg, i);
                haskellsecp256k1_v0_1_0_scalar_set_int(&sk, j);
                haskellsecp256k1_v0_1_0_scalar_get_b32(sk32, &sk);
                haskellsecp256k1_v0_1_0_scalar_get_b32(msg32, &msg);

                haskellsecp256k1_v0_1_0_ecdsa_sign_recoverable(ctx, &rsig, msg32, sk32, haskellsecp256k1_v0_1_0_nonce_function_smallint, &k);

                /* Check directly */
                haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, &rsig);
                r_from_k(&expected_r, group, k, &overflow);
                CHECK(r == expected_r);
                CHECK((k * s) % EXHAUSTIVE_TEST_ORDER == (i + r * j) % EXHAUSTIVE_TEST_ORDER ||
                      (k * (EXHAUSTIVE_TEST_ORDER - s)) % EXHAUSTIVE_TEST_ORDER == (i + r * j) % EXHAUSTIVE_TEST_ORDER);
                /* The recid's second bit is for conveying overflow (R.x value >= group order).
                 * In the actual secp256k1 this is an astronomically unlikely event, but in the
                 * small group used here, it will almost certainly be the case for all points.
                 * Note that this isn't actually useful; full recovery would need to convey
                 * floor(R.x / group_order), but only one bit is used as that is sufficient
                 * in the real group. */
                expected_recid = overflow ? 2 : 0;
                r_dot_y_normalized = group[k].y;
                haskellsecp256k1_v0_1_0_fe_normalize(&r_dot_y_normalized);
                /* Also the recovery id is flipped depending if we hit the low-s branch */
                if ((k * s) % EXHAUSTIVE_TEST_ORDER == (i + r * j) % EXHAUSTIVE_TEST_ORDER) {
                    expected_recid |= haskellsecp256k1_v0_1_0_fe_is_odd(&r_dot_y_normalized);
                } else {
                    expected_recid |= !haskellsecp256k1_v0_1_0_fe_is_odd(&r_dot_y_normalized);
                }
                CHECK(recid == expected_recid);

                /* Convert to a standard sig then check */
                haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_convert(ctx, &sig, &rsig);
                haskellsecp256k1_v0_1_0_ecdsa_signature_load(ctx, &r, &s, &sig);
                /* Note that we compute expected_r *after* signing -- this is important
                 * because our nonce-computing function function might change k during
                 * signing. */
                r_from_k(&expected_r, group, k, NULL);
                CHECK(r == expected_r);
                CHECK((k * s) % EXHAUSTIVE_TEST_ORDER == (i + r * j) % EXHAUSTIVE_TEST_ORDER ||
                      (k * (EXHAUSTIVE_TEST_ORDER - s)) % EXHAUSTIVE_TEST_ORDER == (i + r * j) % EXHAUSTIVE_TEST_ORDER);

                /* Overflow means we've tried every possible nonce */
                if (k < starting_k) {
                    break;
                }
            }
        }
    }
}

static void test_exhaustive_recovery_verify(const haskellsecp256k1_v0_1_0_context *ctx, const haskellsecp256k1_v0_1_0_ge *group) {
    /* This is essentially a copy of test_exhaustive_verify, with recovery added */
    int s, r, msg, key;
    uint64_t iter = 0;
    for (s = 1; s < EXHAUSTIVE_TEST_ORDER; s++) {
        for (r = 1; r < EXHAUSTIVE_TEST_ORDER; r++) {
            for (msg = 1; msg < EXHAUSTIVE_TEST_ORDER; msg++) {
                for (key = 1; key < EXHAUSTIVE_TEST_ORDER; key++) {
                    haskellsecp256k1_v0_1_0_ge nonconst_ge;
                    haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature rsig;
                    haskellsecp256k1_v0_1_0_ecdsa_signature sig;
                    haskellsecp256k1_v0_1_0_pubkey pk;
                    haskellsecp256k1_v0_1_0_scalar sk_s, msg_s, r_s, s_s;
                    haskellsecp256k1_v0_1_0_scalar s_times_k_s, msg_plus_r_times_sk_s;
                    int recid = 0;
                    int k, should_verify;
                    unsigned char msg32[32];

                    if (skip_section(&iter)) continue;

                    haskellsecp256k1_v0_1_0_scalar_set_int(&s_s, s);
                    haskellsecp256k1_v0_1_0_scalar_set_int(&r_s, r);
                    haskellsecp256k1_v0_1_0_scalar_set_int(&msg_s, msg);
                    haskellsecp256k1_v0_1_0_scalar_set_int(&sk_s, key);
                    haskellsecp256k1_v0_1_0_scalar_get_b32(msg32, &msg_s);

                    /* Verify by hand */
                    /* Run through every k value that gives us this r and check that *one* works.
                     * Note there could be none, there could be multiple, ECDSA is weird. */
                    should_verify = 0;
                    for (k = 0; k < EXHAUSTIVE_TEST_ORDER; k++) {
                        haskellsecp256k1_v0_1_0_scalar check_x_s;
                        r_from_k(&check_x_s, group, k, NULL);
                        if (r_s == check_x_s) {
                            haskellsecp256k1_v0_1_0_scalar_set_int(&s_times_k_s, k);
                            haskellsecp256k1_v0_1_0_scalar_mul(&s_times_k_s, &s_times_k_s, &s_s);
                            haskellsecp256k1_v0_1_0_scalar_mul(&msg_plus_r_times_sk_s, &r_s, &sk_s);
                            haskellsecp256k1_v0_1_0_scalar_add(&msg_plus_r_times_sk_s, &msg_plus_r_times_sk_s, &msg_s);
                            should_verify |= haskellsecp256k1_v0_1_0_scalar_eq(&s_times_k_s, &msg_plus_r_times_sk_s);
                        }
                    }
                    /* nb we have a "high s" rule */
                    should_verify &= !haskellsecp256k1_v0_1_0_scalar_is_high(&s_s);

                    /* We would like to try recovering the pubkey and checking that it matches,
                     * but pubkey recovery is impossible in the exhaustive tests (the reason
                     * being that there are 12 nonzero r values, 12 nonzero points, and no
                     * overlap between the sets, so there are no valid signatures). */

                    /* Verify by converting to a standard signature and calling verify */
                    haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_save(&rsig, &r_s, &s_s, recid);
                    haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_convert(ctx, &sig, &rsig);
                    memcpy(&nonconst_ge, &group[sk_s], sizeof(nonconst_ge));
                    haskellsecp256k1_v0_1_0_pubkey_save(&pk, &nonconst_ge);
                    CHECK(should_verify ==
                          haskellsecp256k1_v0_1_0_ecdsa_verify(ctx, &sig, msg32, &pk));
                }
            }
        }
    }
}

static void test_exhaustive_recovery(const haskellsecp256k1_v0_1_0_context *ctx, const haskellsecp256k1_v0_1_0_ge *group) {
    test_exhaustive_recovery_sign(ctx, group);
    test_exhaustive_recovery_verify(ctx, group);
}

#endif /* SECP256K1_MODULE_RECOVERY_EXHAUSTIVE_TESTS_H */
