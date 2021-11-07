/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_BUFFER_H
# define HEADER_BUFFER_H

# include <openssl/ossl_typ.h>
# ifndef HEADER_CRYPTO_H
#  include <openssl/crypto.h>
# endif
# include <openssl/buffererr.h>


#ifdef  __cplusplus
extern "C" {
#endif

# include <stddef.h>
# include <sys/types.h>

/*
 * These names are outdated as of OpenSSL 1.1; a future release
 * will move them to be deprecated.
 */
# define BUF_strdup(s) OPENSSL_strdup(s)
# define BUF_strndup(s, size) OPENSSL_strndup(s, size)
# define BUF_memdup(data, size) OPENSSL_memdup(data, size)
# define BUF_strlcpy(dst, src, size)  OPENSSL_strlcpy(dst, src, size)
# define BUF_strlcat(dst, src, size) OPENSSL_strlcat(dst, src, size)
# define BUF_strnlen(str, maxlen) OPENSSL_strnlen(str, maxlen)

struct buf_mem_st {
    size_t length;              /* current number of bytes */
    char *data;
 