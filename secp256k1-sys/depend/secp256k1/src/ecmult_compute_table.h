/*****************************************************************************************************
 * Copyright (c) 2013, 2014, 2017, 2021 Pieter Wuille, Andrew Poelstra, Jonas Nick, Russell O'Connor *
 * Distributed under the MIT software license, see the accompanying                                  *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.                              *
 *****************************************************************************************************/

#ifndef SECP256K1_ECMULT_COMPUTE_TABLE_H
#define SECP256K1_ECMULT_COMPUTE_TABLE_H

/* Construct table of all odd multiples of gen in range 1..(2**(window_g-1)-1). */
static void haskellsecp256k1_v0_1_0_ecmult_compute_table(haskellsecp256k1_v0_1_0_ge_storage* table, int window_g, const haskellsecp256k1_v0_1_0_gej* gen);

/* Like haskellsecp256k1_v0_1_0_ecmult_compute_table, but one for both gen and gen*2^128. */
static void haskellsecp256k1_v0_1_0_ecmult_compute_two_tables(haskellsecp256k1_v0_1_0_ge_storage* table, haskellsecp256k1_v0_1_0_ge_storage* table_128, int window_g, const haskellsecp256k1_v0_1_0_ge* gen);

#endif /* SECP256K1_ECMULT_COMPUTE_TABLE_H */
