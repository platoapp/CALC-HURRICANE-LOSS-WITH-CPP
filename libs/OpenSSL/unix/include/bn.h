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
# define BN_FLG_SECURE           0x08

# if OPENSSL_API_COMPAT < 0x00908000L
/* deprecated name for the flag */
#  define BN_FLG_EXP_CONSTTIME BN_FLG_CONSTTIME
#  define BN_FLG_FREE            0x8000 /* used for debugging */
# endif

void BN_set_flags(BIGNUM *b, int n);
int BN_get_flags(const BIGNUM *b, int n);

/* Values for |top| in BN_rand() */
#define BN_RAND_TOP_ANY    -1
#define BN_RAND_TOP_ONE     0
#define BN_RAND_TOP_TWO     1

/* Values for |bottom| in BN_rand() */
#define BN_RAND_BOTTOM_ANY  0
#define BN_RAND_BOTTOM_ODD  1

/*
 * get a clone of a BIGNUM with changed flags, for *temporary* use only (the
 * two BIGNUMs cannot be used in parallel!). Also only for *read only* use. The
 * value |dest| should be a newly allocated BIGNUM obtained via BN_new() that
 * has not been otherwise initialised or used.
 */
void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags);

/* Wrapper function to make using BN_GENCB easier */
int BN_GENCB_call(BN_GENCB *cb, int a, int b);

BN_GENCB *BN_GENCB_new(void);
void BN_GENCB_free(BN_GENCB *cb);

/* Populate a BN_GENCB structure with an "old"-style callback */
void BN_GENCB_set_old(BN_GENCB *gencb, void (*callback) (int, int, void *),
                      void *cb_arg);

/* Populate a BN_GENCB structure with a "new"-style callback */
void BN_GENCB_set(BN_GENCB *gencb, int (*callback) (int, int, BN_GENCB *),
                  void *cb_arg);

void *BN_GENCB_get_arg(BN_GENCB *cb);

# define BN_prime_checks 0      /* default: select number of iterations based
                                 * on the size of the number */

/*
 * BN_prime_checks_for_size() returns the number of Miller-Rabin iterations
 * that will be done for checking that a random number is probably prime. The
 * error rate for accepting a composite number as prime depends on the size of
 * the prime |b|. The error rates used are for calculating an RSA key with 2 primes,
 * and so the level is what you would expect for a key of double the size of the
 * prime.
 *
 * This table is generated using the algorithm of FIPS PUB 186-4
 * Digital Signature Standard (DSS), section F.1, page 117.
 * (https://dx.doi.org/10.6028/NIST.FIPS.186-4)
 *
 * The following magma script was used to generate the output:
 * securitybits:=125;
 * k:=1024;
 * for t:=1 to 65 do
 *   for M:=3 to Floor(2*Sqrt(k-1)-1) do
 *     S:=0;
 *     // Sum over m
 *     for m:=3 to M do
 *       s:=0;
 *       // Sum over j
 *       for j:=2 to m do
 *         s+:=(RealField(32)!2)^-(j+(k-1)/j);
 *       end for;
 *       S+:=2^(m-(m-1)*t)*s;
 *     end for;
 *     A:=2^(k-2-M*t);
 *     B:=8*(Pi(RealField(32))^2-6)/3*2^(k-2)*S;
 *     pkt:=2.00743*Log(2)*k*2^-k*(A+B);
 *     seclevel:=Floor(-Log(2,pkt));
 *     if seclevel ge securitybits then
 *       printf "k: %5o, security: %o bits  (t: %o, M: %o)\n",k,seclevel,t,M;
 *       break;
 *     end if;
 *   end for;
 *   if seclevel ge securitybits then break; end if;
 * end for;
 *
 * It can be run online at:
 * http://magma.maths.usyd.edu.au/calc
 *
 * And will output:
 * k:  1024, security: 129 bits  (t: 6, M: 23)
 *
 * k is the number of bits of the prime, securitybits is the level we want to
 * reach.
 *
 * prime length | RSA key size | # MR tests | security level
 * -------------+--------------|------------+---------------
 *  (b) >= 6394 |     >= 12788 |          3 |        256 bit
 *  (b) >= 3747 |     >=  7494 |          3 |        192 bit
 *  (b) >= 1345 |     >=  2690 |          4 |        128 bit
 *  (b) >= 1080 |     >=  2160 |          5 |        128 bit
 *  (b) >=  852 |     >=  1704 |          5 |        112 bit
 *  (b) >=  476 |     >=   952 |          5 |         80 bit
 *  (b) >=  400 |     >=   800 |          6 |         80 bit
 *  (b) >=  347 |     >=   694 |          7 |         80 bit
 *  (b) >=  308 |     >=   616 |          8 |         80 bit
 *  (b) >=   55 |     >=   110 |         27 