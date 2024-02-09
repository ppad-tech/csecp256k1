/***********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SCRATCH_H
#define SECP256K1_SCRATCH_H

/* The typedef is used internally; the struct name is used in the public API
 * (where it is exposed as a different typedef) */
typedef struct haskellsecp256k1_v0_1_0_scratch_space_struct {
    /** guard against interpreting this object as other types */
    unsigned char magic[8];
    /** actual allocated data */
    void *data;
    /** amount that has been allocated (i.e. `data + offset` is the next
     *  available pointer)  */
    size_t alloc_size;
    /** maximum size available to allocate */
    size_t max_size;
} haskellsecp256k1_v0_1_0_scratch;

static haskellsecp256k1_v0_1_0_scratch* haskellsecp256k1_v0_1_0_scratch_create(const haskellsecp256k1_v0_1_0_callback* error_callback, size_t max_size);

static void haskellsecp256k1_v0_1_0_scratch_destroy(const haskellsecp256k1_v0_1_0_callback* error_callback, haskellsecp256k1_v0_1_0_scratch* scratch);

/** Returns an opaque object used to "checkpoint" a scratch space. Used
 *  with `haskellsecp256k1_v0_1_0_scratch_apply_checkpoint` to undo allocations. */
static size_t haskellsecp256k1_v0_1_0_scratch_checkpoint(const haskellsecp256k1_v0_1_0_callback* error_callback, const haskellsecp256k1_v0_1_0_scratch* scratch);

/** Applies a check point received from `haskellsecp256k1_v0_1_0_scratch_checkpoint`,
 *  undoing all allocations since that point. */
static void haskellsecp256k1_v0_1_0_scratch_apply_checkpoint(const haskellsecp256k1_v0_1_0_callback* error_callback, haskellsecp256k1_v0_1_0_scratch* scratch, size_t checkpoint);

/** Returns the maximum allocation the scratch space will allow */
static size_t haskellsecp256k1_v0_1_0_scratch_max_allocation(const haskellsecp256k1_v0_1_0_callback* error_callback, const haskellsecp256k1_v0_1_0_scratch* scratch, size_t n_objects);

/** Returns a pointer into the most recently allocated frame, or NULL if there is insufficient available space */
static void *haskellsecp256k1_v0_1_0_scratch_alloc(const haskellsecp256k1_v0_1_0_callback* error_callback, haskellsecp256k1_v0_1_0_scratch* scratch, size_t n);

#endif
