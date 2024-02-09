/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ELLSWIFT_TESTS_EXHAUSTIVE_H
#define SECP256K1_MODULE_ELLSWIFT_TESTS_EXHAUSTIVE_H

#include "../../../include/secp256k1_ellswift.h"
#include "main_impl.h"

static void test_exhaustive_ellswift(const haskellsecp256k1_v0_1_0_context *ctx, const haskellsecp256k1_v0_1_0_ge *group) {
    int i;

    /* Note that SwiftEC/ElligatorSwift are inherently curve operations, not
     * group operations, and this test only checks the curve points which are in
     * a tiny subgroup. In that sense it can't be really seen as exhaustive as
     * it doesn't (and for computational reasons obviously cannot) test the
     * entire domain ellswift operates under. */
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; i++) {
        haskellsecp256k1_v0_1_0_scalar scalar_i;
        unsigned char sec32[32];
        unsigned char ell64[64];
        haskellsecp256k1_v0_1_0_pubkey pub_decoded;
        haskellsecp256k1_v0_1_0_ge ge_decoded;

        /* Construct ellswift pubkey from exhaustive loop scalar i. */
        haskellsecp256k1_v0_1_0_scalar_set_int(&scalar_i, i);
        haskellsecp256k1_v0_1_0_scalar_get_b32(sec32, &scalar_i);
        CHECK(haskellsecp256k1_v0_1_0_ellswift_create(ctx, ell64, sec32, NULL));

        /* Decode ellswift pubkey and check that it matches the precomputed group element. */
        haskellsecp256k1_v0_1_0_ellswift_decode(ctx, &pub_decoded, ell64);
        haskellsecp256k1_v0_1_0_pubkey_load(ctx, &ge_decoded, &pub_decoded);
        CHECK(haskellsecp256k1_v0_1_0_ge_eq_var(&ge_decoded, &group[i]));
    }
}

#endif
