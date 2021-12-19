/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_HMAC_H
# define HEADER_HMAC_H

# include <openssl/opensslconf.h>

# include <openssl/evp.h>

# if OPENSSL_API_COMPAT < 0x10200000L
#  define HMAC_MAX_MD_CBLOCK      128    /* Deprecated */
# endif

#ifdef  __cplusplus
extern "C" {
#endif

size_t HMAC_size(const HMAC_CTX *e);
HMAC_CTX *HMAC_CTX_new(void);
int HMAC_CTX_reset(HMAC_CTX *ctx);
void HMAC_CTX_free(HMAC_CTX *ctx);

DEPRECATEDIN_1_1_0(__owur int HMAC_Init(HMAC_CTX *ctx, const void *key, int len,
                  