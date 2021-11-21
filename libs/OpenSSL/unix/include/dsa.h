/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_DSA_H
# define HEADER_DSA_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_DSA
# ifdef  __cplusplus
extern "C" {
# endif
# include <openssl/e_os2.h>
# include <openssl/bio.h>
# include <openssl/crypto.h>
# include <openssl/ossl_typ.h>
# include <openssl/bn.h>
# if OPENSSL_API_COMPAT < 0x10100000L
#  include <openssl/dh.h>
# endif
# include <openssl/dsaerr.h>

# ifndef OPENSSL_DSA_MAX_MODULUS_BITS
#  define OPENSSL_DSA_MAX_MODULUS_BITS   10000
# endif

# define OPENSSL_DSA_FIPS_MIN_MODULUS_BITS 1024

# define DSA_FLAG_CACHE_MONT_P   0x01
# if OPENSSL_API_COMPAT < 0x10100000L
/*
 * Does nothing. Previously this switched off constant time behaviour.
 */
#  define DSA_FLAG_NO_EXP_CONSTTIME       0x00
# endif

/*
 * If this flag is set the DSA method is FIPS compliant and can be used in
 * FIPS mode. This is set in the validated module method. If an application
 * sets this flag in its own methods it is its responsibility to ensure the
 * result is compliant.
 */

# define DSA_FLAG_FIPS_METHOD                    0x0400

/*
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */

# define DSA_FLAG_NON_FIPS_ALLOW                 0x0400
# define DSA_FLAG_FIPS_CHECKED                   0x0800

/* Already defined in ossl_typ.h */
/* typedef struct dsa_st DSA; */
/* typedef struct dsa_method DSA_METHOD; */

typedef struct DSA_SIG_st DSA_SIG;

# define d2i_DSAparams_fp(fp,x) (DSA *)ASN1_d2i_fp((char *(*)())DSA_new, \
                (char *(*)())d2i_DSAparams,(fp),(unsigned char **)(x))
