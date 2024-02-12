/***********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SCRATCH_IMPL_H
#define SECP256K1_SCRATCH_IMPL_H

#include "util.h"
#include "scratch.h"

static haskellsecp256k1_v0_1_0_scratch* haskellsecp256k1_v0_1_0_scratch_create(const haskellsecp256k1_v0_1_0_callback* error_callback, size_t size) {
    const size_t base_alloc = ROUND_TO_ALIGN(sizeof(haskellsecp256k1_v0_1_0_scratch));
    void *alloc = checked_malloc(error_callback, base_alloc + size);
    haskellsecp256k1_v0_1_0_scratch* ret = (haskellsecp256k1_v0_1_0_scratch *)alloc;
    if (ret != NULL) {
        memset(ret, 0, sizeof(*ret));
        memcpy(ret->magic, "scratch", 8);
        ret->data = (void *) ((char *) alloc + base_alloc);
        ret->max_size = size;
    }
    return ret;
}

static void haskellsecp256k1_v0_1_0_scratch_destroy(const haskellsecp256k1_v0_1_0_callback* error_callback, haskellsecp256k1_v0_1_0_scratch* scratch) {
    if (scratch != NULL) {
        if (haskellsecp256k1_v0_1_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
            haskellsecp256k1_v0_1_0_callback_call(error_callback, "invalid scratch space");
            return;
        }
        VERIFY_CHECK(scratch->alloc_size == 0); /* all checkpoints should be applied */
        memset(scratch->magic, 0, sizeof(scratch->magic));
        free(scratch);
    }
}

static size_t haskellsecp256k1_v0_1_0_scratch_checkpoint(const haskellsecp256k1_v0_1_0_callback* error_callback, const haskellsecp256k1_v0_1_0_scratch* scratch) {
    if (haskellsecp256k1_v0_1_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        haskellsecp256k1_v0_1_0_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    return scratch->alloc_size;
}

static void haskellsecp256k1_v0_1_0_scratch_apply_checkpoint(const haskellsecp256k1_v0_1_0_callback* error_callback, haskellsecp256k1_v0_1_0_scratch* scratch, size_t checkpoint) {
    if (haskellsecp256k1_v0_1_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        haskellsecp256k1_v0_1_0_callback_call(error_callback, "invalid scratch space");
        return;
    }
    if (checkpoint > scratch->alloc_size) {
        haskellsecp256k1_v0_1_0_callback_call(error_callback, "invalid checkpoint");
        return;
    }
    scratch->alloc_size = checkpoint;
}

static size_t haskellsecp256k1_v0_1_0_scratch_max_allocation(const haskellsecp256k1_v0_1_0_callback* error_callback, const haskellsecp256k1_v0_1_0_scratch* scratch, size_t objects) {
    if (haskellsecp256k1_v0_1_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        haskellsecp256k1_v0_1_0_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    /* Ensure that multiplication will not wrap around */
    if (ALIGNMENT > 1 && objects > SIZE_MAX/(ALIGNMENT - 1)) {
        return 0;
    }
    if (scratch->max_size - scratch->alloc_size <= objects * (ALIGNMENT - 1)) {
        return 0;
    }
    return scratch->max_size - scratch->alloc_size - objects * (ALIGNMENT - 1);
}

static void *haskellsecp256k1_v0_1_0_scratch_alloc(const haskellsecp256k1_v0_1_0_callback* error_callback, haskellsecp256k1_v0_1_0_scratch* scratch, size_t size) {
    void *ret;
    size_t rounded_size;

    rounded_size = ROUND_TO_ALIGN(size);
    /* Check that rounding did not wrap around */
    if (rounded_size < size) {
        return NULL;
    }
    size = rounded_size;

    if (haskellsecp256k1_v0_1_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        haskellsecp256k1_v0_1_0_callback_call(error_callback, "invalid scratch space");
        return NULL;
    }

    if (size > scratch->max_size - scratch->alloc_size) {
        return NULL;
    }
    ret = (void *) ((char *) scratch->data + scratch->alloc_size);
    memset(ret, 0, size);
    scratch->alloc_size += size;

    return ret;
}

#endif
