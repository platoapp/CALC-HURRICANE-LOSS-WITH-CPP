/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_DES_H
# define HEADER_DES_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_DES
# ifdef  __cplusplus
extern "C" {
# endif
# include <openssl/e_os2.h>

typedef unsigned int DES_LONG;

# ifdef OPENSSL_BUILD_SHLIBCRYPTO
#  undef OPENSSL_EXTERN
#  define OPENSSL_EXTERN OPENSSL_EXPORT
# endif

typedef unsigned char DES_cblock[8];
typedef /* const */ unsigned char const_DES_cblock[8];
/*
 * With "const", gcc 2.8.1 on Solaris thinks that DES_cblock * and
 * const_DES_cblock * are incompatible pointer types.
 */

typedef struct DES_ks {
    union {
        DES_cblock cblock;
        /*
         * make sure things are correct size on machines with 8 byte longs
         */
        DES_LONG deslong[2];
    } ks[16];
} DES_key_schedule;

# define DES_KEY_SZ      (sizeof(DES_cblock))
# define DES_SCHEDULE_SZ (sizeof(DES_key_schedule))

# define DES_ENCRYPT     1
# define DES_DECRYPT     0

# define DES_CBC_MODE    0
# define DES_PCBC_MODE   1

# define DES_ecb2_encrypt(i,o,k1,k2,e) \
        DES_ecb3_encrypt((i),(o),(k1),(k2),(k1),(e))

# define DES_ede2_cbc_encrypt(i,o,l,k1,k2,iv,e) \
        DES_ede3_cbc_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(e))

# define DES_ede2_cfb64_encrypt(i,o,l,k1,k2,iv,n,e) \
        DES_ede3_cfb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n),(e))

# define DES_ede2_ofb64_encrypt(i,o,l,k1,k2,iv,n) \
        DES_ede3_ofb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n))

OPENSSL_DECLARE_GLOBAL(int, DES_check_key); /* defaults to false */
# define DES_check_key OPENSSL_GLOBAL_REF(DES_check_key)

const char *DES_options(void);
void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output,
                      DES_key_schedule *ks1, DES_key_schedule *ks2,
                      DES_key_schedule *ks3, int enc);
DES_LONG DES_cbc_cksum(const unsigned char *input, DES_cblock *output,
                       long length, DES_key_schedule *schedule,
                       const_DES_cblock *ivec);
/* DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead. */
void DES_cbc_encrypt(const unsigned char *input, unsigned char *output,
                     long length, DES_key_schedule *schedule,
                     DES_cblock *ivec, int enc);
void DES_ncbc_encrypt(const unsigned char *input, unsigned char *output,
                      long length, DES_key_schedule *schedule,
      