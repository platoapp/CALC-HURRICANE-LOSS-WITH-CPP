/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CRYPTOERR_H
# define HEADER_CRYPTOERR_H

# ifndef HEADER_SYMHACKS_H
#  include <openssl/symhacks.h>
# endif

# ifdef  __cplusplus
extern "C"
# endif
int ERR_load_CRYPTO_strings(void);

/*
 * CRYPTO function codes.
 */
# define CRYPTO_F_CMAC_CTX_NEW                            120
# define CRYPTO_F_CRYPTO_DUP_EX_DATA                      110
# define CRYPTO_F_CRYPTO_FREE_EX_DATA                     111
# define CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX                 100
# define CRYPTO_F_CRYPTO_MEMDUP                           115
# define CRYPTO_F_CRYPTO_NEW_EX_DATA                      112
# define CRYPTO_F_CRYPTO_OCB128_COPY_CTX                  121
# define CRYPTO_F_CR