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
typedef /* 