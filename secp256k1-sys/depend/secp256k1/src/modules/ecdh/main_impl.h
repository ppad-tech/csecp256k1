/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ECDH_MAIN_H
#define SECP256K1_MODULE_ECDH_MAIN_H

#include "../../../include/secp256k1_ecdh.h"
#include "../../ecmult_const_impl.h"

static int ecdh_hash_function_sha256(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    unsigned char version = (y32[31] & 0x01) | 0x02;
    haskellsecp256k1_v0_1_0_sha256 sha;
    (void)data;

    haskellsecp256k1_v0_1_0_sha256_initialize(&sha);
    haskellsecp256k1_v0_1_0_sha256_write(&sha, &version, 1);
    haskellsecp256k1_v0_1_0_sha256_write(&sha, x32, 32);
    haskellsecp256k1_v0_1_0_sha256_finalize(&sha, output);

    return 1;
}

const haskellsecp256k1_v0_1_0_ecdh_hash_function haskellsecp256k1_v0_1_0_ecdh_hash_function_sha256 = ecdh_hash_function_sha256;
const haskellsecp256k1_v0_1_0_ecdh_hash_function haskellsecp256k1_v0_1_0_ecdh_hash_function_default = ecdh_hash_function_sha256;

int haskellsecp256k1_v0_1_0_ecdh(const haskellsecp256k1_v0_1_0_context* ctx, unsigned char *output, const haskellsecp256k1_v0_1_0_pubkey *point, const unsigned char *scalar, haskellsecp256k1_v0_1_0_ecdh_hash_function hashfp, void *data) {
    int ret = 0;
    int overflow = 0;
    haskellsecp256k1_v0_1_0_gej res;
    haskellsecp256k1_v0_1_0_ge pt;
    haskellsecp256k1_v0_1_0_scalar s;
    unsigned char x[32];
    unsigned char y[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);

    if (hashfp == NULL) {
        hashfp = haskellsecp256k1_v0_1_0_ecdh_hash_function_default;
    }

    haskellsecp256k1_v0_1_0_pubkey_load(ctx, &pt, point);
    haskellsecp256k1_v0_1_0_scalar_set_b32(&s, scalar, &overflow);

    overflow |= haskellsecp256k1_v0_1_0_scalar_is_zero(&s);
    haskellsecp256k1_v0_1_0_scalar_cmov(&s, &haskellsecp256k1_v0_1_0_scalar_one, overflow);

    haskellsecp256k1_v0_1_0_ecmult_const(&res, &pt, &s);
    haskellsecp256k1_v0_1_0_ge_set_gej(&pt, &res);

    /* Compute a hash of the point */
    haskellsecp256k1_v0_1_0_fe_normalize(&pt.x);
    haskellsecp256k1_v0_1_0_fe_normalize(&pt.y);
    haskellsecp256k1_v0_1_0_fe_get_b32(x, &pt.x);
    haskellsecp256k1_v0_1_0_fe_get_b32(y, &pt.y);

    ret = hashfp(output, x, y, data);

    memset(x, 0, 32);
    memset(y, 0, 32);
    haskellsecp256k1_v0_1_0_scalar_clear(&s);

    return !!ret & !overflow;
}

#endif /* SECP256K1_MODULE_ECDH_MAIN_H */
