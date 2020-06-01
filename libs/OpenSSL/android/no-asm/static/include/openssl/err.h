/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ERR_H
# define HEADER_ERR_H

# include <openssl/e_os2.h>

# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
#  include <stdlib.h>
# endif

# include <openssl/ossl_typ.h>
# include <openssl/bio.h>
# include <openssl/lhash.h>

#ifdef  __cplusplus
extern "C" {
#endif

# ifndef OPENSSL_NO_ERR
#  define ERR_PUT_error(a,b,c,d,e)        ERR_