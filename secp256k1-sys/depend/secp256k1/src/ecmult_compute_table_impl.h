/*****************************************************************************************************
 * Copyright (c) 2013, 2014, 2017, 2021 Pieter Wuille, Andrew Poelstra, Jonas Nick, Russell O'Connor *
 * Distributed under the MIT software license, see the accompanying                                  *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.                              *
 *****************************************************************************************************/

#ifndef SECP256K1_ECMULT_COMPUTE_TABLE_IMPL_H
#define SECP256K1_ECMULT_COMPUTE_TABLE_IMPL_H

#include "ecmult_compute_table.h"
#include "group_impl.h"
#include "field_impl.h"
#include "ecmult.h"
#include "util.h"

static void haskellsecp256k1_v0_1_0_ecmult_compute_table(haskellsecp256k1_v0_1_0_ge_storage* table, int window_g, const haskellsecp256k1_v0_1_0_gej* gen) {
    haskellsecp256k1_v0_1_0_gej gj;
    haskellsecp256k1_v0_1_0_ge ge, dgen;
    int j;

    gj = *gen;
    haskellsecp256k1_v0_1_0_ge_set_gej_var(&ge, &gj);
    haskellsecp256k1_v0_1_0_ge_to_storage(&table[0], &ge);

    haskellsecp256k1_v0_1_0_gej_double_var(&gj, gen, NULL);
    haskellsecp256k1_v0_1_0_ge_set_gej_var(&dgen, &gj);

    for (j = 1; j < ECMULT_TABLE_SIZE(window_g); ++j) {
        haskellsecp256k1_v0_1_0_gej_set_ge(&gj, &ge);
        haskellsecp256k1_v0_1_0_gej_add_ge_var(&gj, &gj, &dgen, NULL);
        haskellsecp256k1_v0_1_0_ge_set_gej_var(&ge, &gj);
        haskellsecp256k1_v0_1_0_ge_to_storage(&table[j], &ge);
    }
}

/* Like haskellsecp256k1_v0_1_0_ecmult_compute_table, but one for both gen and gen*2^128. */
static void haskellsecp256k1_v0_1_0_ecmult_compute_two_tables(haskellsecp256k1_v0_1_0_ge_storage* table, haskellsecp256k1_v0_1_0_ge_storage* table_128, int window_g, const haskellsecp256k1_v0_1_0_ge* gen) {
    haskellsecp256k1_v0_1_0_gej gj;
    int i;

    haskellsecp256k1_v0_1_0_gej_set_ge(&gj, gen);
    haskellsecp256k1_v0_1_0_ecmult_compute_table(table, window_g, &gj);
    for (i = 0; i < 128; ++i) {
        haskellsecp256k1_v0_1_0_gej_double_var(&gj, &gj, NULL);
    }
    haskellsecp256k1_v0_1_0_ecmult_compute_table(table_128, window_g, &gj);
}

#endif /* SECP256K1_ECMULT_COMPUTE_TABLE_IMPL_H */
