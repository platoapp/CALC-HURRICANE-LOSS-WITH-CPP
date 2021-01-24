/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_RC5_H
# define HEADER_RC5_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_RC5
# ifdef  __cplusplus
extern "C" {
# endif

# define RC5_ENCRYPT     1
# define RC5_DECRYPT     0

# define RC5_32_INT unsigned int

# define RC5_32_BLOCK            8
# define RC5_32_KEY_LENGTH     