/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECDSA_H
#define SECP256K1_ECDSA_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int haskellsecp256k1_v0_1_0_ecdsa_sig_parse(haskellsecp256k1_v0_1_0_scalar *r, haskellsecp256k1_v0_1_0_scalar *s, const unsigned char *sig, size_t size);
static int haskellsecp256k1_v0_1_0_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const haskellsecp256k1_v0_1_0_scalar *r, const haskellsecp256k1_v0_1_0_scalar *s);
static int haskellsecp256k1_v0_1_0_ecdsa_sig_verify(const haskellsecp256k1_v0_1_0_scalar* r, const haskellsecp256k1_v0_1_0_scalar* s, const haskellsecp256k1_v0_1_0_ge *pubkey, const haskellsecp256k1_v0_1_0_scalar *message);
static int haskellsecp256k1_v0_1_0_ecdsa_sig_sign(const haskellsecp256k1_v0_1_0_ecmult_gen_context *ctx, haskellsecp256k1_v0_1_0_scalar* r, haskellsecp256k1_v0_1_0_scalar* s, const haskellsecp256k1_v0_1_0_scalar *seckey, const haskellsecp256k1_v0_1_0_scalar *message, const haskellsecp256k1_v0_1_0_scalar *nonce, int *recid);

#endif /* SECP256K1_ECDSA_H */
