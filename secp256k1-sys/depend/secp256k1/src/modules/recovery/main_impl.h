/***********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_RECOVERY_MAIN_H
#define SECP256K1_MODULE_RECOVERY_MAIN_H

#include "../../../include/secp256k1_recovery.h"

static void haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_load(const haskellsecp256k1_v0_1_0_context* ctx, haskellsecp256k1_v0_1_0_scalar* r, haskellsecp256k1_v0_1_0_scalar* s, int* recid, const haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature* sig) {
    (void)ctx;
    if (sizeof(haskellsecp256k1_v0_1_0_scalar) == 32) {
        /* When the haskellsecp256k1_v0_1_0_scalar type is exactly 32 byte, use its
         * representation inside haskellsecp256k1_v0_1_0_ecdsa_signature, as conversion is very fast.
         * Note that haskellsecp256k1_v0_1_0_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        haskellsecp256k1_v0_1_0_scalar_set_b32(r, &sig->data[0], NULL);
        haskellsecp256k1_v0_1_0_scalar_set_b32(s, &sig->data[32], NULL);
    }
    *recid = sig->data[64];
}

static void haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_save(haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature* sig, const haskellsecp256k1_v0_1_0_scalar* r, const haskellsecp256k1_v0_1_0_scalar* s, int recid) {
    if (sizeof(haskellsecp256k1_v0_1_0_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        haskellsecp256k1_v0_1_0_scalar_get_b32(&sig->data[0], r);
        haskellsecp256k1_v0_1_0_scalar_get_b32(&sig->data[32], s);
    }
    sig->data[64] = recid;
}

int haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_parse_compact(const haskellsecp256k1_v0_1_0_context* ctx, haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature* sig, const unsigned char *input64, int recid) {
    haskellsecp256k1_v0_1_0_scalar r, s;
    int ret = 1;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);
    ARG_CHECK(recid >= 0 && recid <= 3);

    haskellsecp256k1_v0_1_0_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    haskellsecp256k1_v0_1_0_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_save(sig, &r, &s, recid);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_serialize_compact(const haskellsecp256k1_v0_1_0_context* ctx, unsigned char *output64, int *recid, const haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature* sig) {
    haskellsecp256k1_v0_1_0_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(recid != NULL);

    haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_load(ctx, &r, &s, recid, sig);
    haskellsecp256k1_v0_1_0_scalar_get_b32(&output64[0], &r);
    haskellsecp256k1_v0_1_0_scalar_get_b32(&output64[32], &s);
    return 1;
}

int haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_convert(const haskellsecp256k1_v0_1_0_context* ctx, haskellsecp256k1_v0_1_0_ecdsa_signature* sig, const haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature* sigin) {
    haskellsecp256k1_v0_1_0_scalar r, s;
    int recid;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(sigin != NULL);

    haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, sigin);
    haskellsecp256k1_v0_1_0_ecdsa_signature_save(sig, &r, &s);
    return 1;
}

static int haskellsecp256k1_v0_1_0_ecdsa_sig_recover(const haskellsecp256k1_v0_1_0_scalar *sigr, const haskellsecp256k1_v0_1_0_scalar* sigs, haskellsecp256k1_v0_1_0_ge *pubkey, const haskellsecp256k1_v0_1_0_scalar *message, int recid) {
    unsigned char brx[32];
    haskellsecp256k1_v0_1_0_fe fx;
    haskellsecp256k1_v0_1_0_ge x;
    haskellsecp256k1_v0_1_0_gej xj;
    haskellsecp256k1_v0_1_0_scalar rn, u1, u2;
    haskellsecp256k1_v0_1_0_gej qj;
    int r;

    if (haskellsecp256k1_v0_1_0_scalar_is_zero(sigr) || haskellsecp256k1_v0_1_0_scalar_is_zero(sigs)) {
        return 0;
    }

    haskellsecp256k1_v0_1_0_scalar_get_b32(brx, sigr);
    r = haskellsecp256k1_v0_1_0_fe_set_b32_limit(&fx, brx);
    (void)r;
    VERIFY_CHECK(r); /* brx comes from a scalar, so is less than the order; certainly less than p */
    if (recid & 2) {
        if (haskellsecp256k1_v0_1_0_fe_cmp_var(&fx, &haskellsecp256k1_v0_1_0_ecdsa_const_p_minus_order) >= 0) {
            return 0;
        }
        haskellsecp256k1_v0_1_0_fe_add(&fx, &haskellsecp256k1_v0_1_0_ecdsa_const_order_as_fe);
    }
    if (!haskellsecp256k1_v0_1_0_ge_set_xo_var(&x, &fx, recid & 1)) {
        return 0;
    }
    haskellsecp256k1_v0_1_0_gej_set_ge(&xj, &x);
    haskellsecp256k1_v0_1_0_scalar_inverse_var(&rn, sigr);
    haskellsecp256k1_v0_1_0_scalar_mul(&u1, &rn, message);
    haskellsecp256k1_v0_1_0_scalar_negate(&u1, &u1);
    haskellsecp256k1_v0_1_0_scalar_mul(&u2, &rn, sigs);
    haskellsecp256k1_v0_1_0_ecmult(&qj, &xj, &u2, &u1);
    haskellsecp256k1_v0_1_0_ge_set_gej_var(pubkey, &qj);
    return !haskellsecp256k1_v0_1_0_gej_is_infinity(&qj);
}

int haskellsecp256k1_v0_1_0_ecdsa_sign_recoverable(const haskellsecp256k1_v0_1_0_context* ctx, haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature *signature, const unsigned char *msghash32, const unsigned char *seckey, haskellsecp256k1_v0_1_0_nonce_function noncefp, const void* noncedata) {
    haskellsecp256k1_v0_1_0_scalar r, s;
    int ret, recid;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(haskellsecp256k1_v0_1_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);

    ret = haskellsecp256k1_v0_1_0_ecdsa_sign_inner(ctx, &r, &s, &recid, msghash32, seckey, noncefp, noncedata);
    haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_save(signature, &r, &s, recid);
    return ret;
}

int haskellsecp256k1_v0_1_0_ecdsa_recover(const haskellsecp256k1_v0_1_0_context* ctx, haskellsecp256k1_v0_1_0_pubkey *pubkey, const haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature *signature, const unsigned char *msghash32) {
    haskellsecp256k1_v0_1_0_ge q;
    haskellsecp256k1_v0_1_0_scalar r, s;
    haskellsecp256k1_v0_1_0_scalar m;
    int recid;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(pubkey != NULL);

    haskellsecp256k1_v0_1_0_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, signature);
    VERIFY_CHECK(recid >= 0 && recid < 4);  /* should have been caught in parse_compact */
    haskellsecp256k1_v0_1_0_scalar_set_b32(&m, msghash32, NULL);
    if (haskellsecp256k1_v0_1_0_ecdsa_sig_recover(&r, &s, &q, &m, recid)) {
        haskellsecp256k1_v0_1_0_pubkey_save(pubkey, &q);
        return 1;
    } else {
        memset(pubkey, 0, sizeof(*pubkey));
        return 0;
    }
}

#endif /* SECP256K1_MODULE_RECOVERY_MAIN_H */
