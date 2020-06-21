/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ENVELOPE_H
# define HEADER_ENVELOPE_H

# include <openssl/opensslconf.h>
# include <openssl/ossl_typ.h>
# include <openssl/symhacks.h>
# include <openssl/bio.h>
# include <openssl/evperr.h>

# define EVP_MAX_MD_SIZE                 64/* longest known is SHA512 */
# define EVP_MAX_KEY_LENGTH              64
# define EVP_MAX_IV_LENGTH               16
# define EVP_MAX_BLOCK_LENGTH            32

# define PKCS5_SALT_LEN                  8
/* Default PKCS#5 iteration count */
# define PKCS5_DEFAULT_ITER              2048

# include <openssl/objects.h>

# define EVP_PK_RSA      0x0001
# define EVP_PK_DSA      0x0002
# define EVP_PK_DH       0x0004
# define EVP_PK_EC       0x0008
# define EVP_PKT_SIGN    0x0010
# define EVP_PKT_ENC     0x0020
# define EVP_PKT_EXCH    0x0040
# define EVP_PKS_RSA     0x0100
# define EVP_PKS_DSA     0x0200
# define EVP_PKS_EC      0x0400

# define EVP_PKEY_NONE  