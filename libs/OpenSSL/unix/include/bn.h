/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_BN_H
# define HEADER_BN_H

# include <openssl/e_os2.h>
# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include <openssl/opensslconf.h>
# include <openssl/ossl_typ.h>
# include <openssl/crypto.h>
# include <openssl/bnerr.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * 64-bit processor with LP64 ABI
 */
# ifdef SIXTY_FOUR_BIT_LONG
#  define BN_ULONG        unsigned long
#  define BN_BYTES        8
# endif

/*
 * 64-bit processor other than LP64 ABI
 */
# ifdef SIXTY_FOUR_BIT
#  define BN_ULONG        unsigned long long
#  define BN_BYTES        8
# endif

# ifdef THIRTY_TWO_BIT
#  define BN_ULONG        unsigned int
#  define BN_BYTES        4
# endif

# define BN_BITS2       (BN_BYTES * 8)
# define BN_BITS        (BN_BITS2 * 2)
# define BN_TBIT        ((BN_ULONG)1 << (BN_BITS2 - 1))

# define BN_FLG_MALLOCED         0x01
# define BN_FLG_STATIC_DATA      0x02

/*
 * avoid leaking exponent information through timing,
 * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
 * BN_div() will call BN_div_no_branch,
 * BN_mod_inverse() will call bn_mod_inverse_no_branch.
 */
# define BN_FLG_CONSTTIME        0x04
# define BN_FLG_SECURE           