/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_HASH_H
#define SECP256K1_HASH_H

#include <stdlib.h>
#include <stdint.h>

typedef struct {
    uint32_t s[8];
    unsigned char buf[64];
    uint64_t bytes;
} haskellsecp256k1_v0_1_0_sha256;

static void haskellsecp256k1_v0_1_0_sha256_initialize(haskellsecp256k1_v0_1_0_sha256 *hash);
static void haskellsecp256k1_v0_1_0_sha256_write(haskellsecp256k1_v0_1_0_sha256 *hash, const unsigned char *data, size_t size);
static void haskellsecp256k1_v0_1_0_sha256_finalize(haskellsecp256k1_v0_1_0_sha256 *hash, unsigned char *out32);

typedef struct {
    haskellsecp256k1_v0_1_0_sha256 inner, outer;
} haskellsecp256k1_v0_1_0_hmac_sha256;

static void haskellsecp256k1_v0_1_0_hmac_sha256_initialize(haskellsecp256k1_v0_1_0_hmac_sha256 *hash, const unsigned char *key, size_t size);
static void haskellsecp256k1_v0_1_0_hmac_sha256_write(haskellsecp256k1_v0_1_0_hmac_sha256 *hash, const unsigned char *data, size_t size);
static void haskellsecp256k1_v0_1_0_hmac_sha256_finalize(haskellsecp256k1_v0_1_0_hmac_sha256 *hash, unsigned char *out32);

typedef struct {
    unsigned char v[32];
    unsigned char k[32];
    int retry;
} haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256;

static void haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256_initialize(haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256 *rng, const unsigned char *key, size_t keylen);
static void haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256_generate(haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256 *rng, unsigned char *out, size_t outlen);
static void haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256_finalize(haskellsecp256k1_v0_1_0_rfc6979_hmac_sha256 *rng);

#endif /* SECP256K1_HASH_H */
