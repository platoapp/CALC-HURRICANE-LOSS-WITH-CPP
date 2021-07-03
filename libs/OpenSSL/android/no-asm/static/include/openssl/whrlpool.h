/*
 * Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_WHRLPOOL_H
# define HEADER_WHRLPOOL_H

#include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_WHIRLPOOL
# include <openssl/e_os2.h>
# include <stddef.h>
# ifdef __cplusplus
extern "C" {
# endif

# define WHIRLPOOL_DIGEST_LENGTH (512/8)
# define WHIRLPOOL_BBLOCK        512
# define WHIRLPOOL_COUNTER       (256/8)

typedef struct {
    uni