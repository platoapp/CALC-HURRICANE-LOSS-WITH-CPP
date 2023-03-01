/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_UI_H
# define HEADER_UI_H

# include <openssl/opensslconf.h>

# if OPENSSL_API_COMPAT < 0x10100000L
#  include <openssl/crypto.h>
# endif
# include <openssl/safestack.h>
# include <openssl/pem.h>
# include <openssl/ossl_typ.h>
# include <openssl/uierr.h>

/* For compatibility reasons, the macro OPENSSL_NO_UI is currently retained */
# if OPENSSL_API_COMPAT < 0x10200000L
#  ifdef OPENSSL_NO_UI_CONSOLE
#   define OPENSSL_NO_UI
#  endif
# endif

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * All the following functions return -1 or NULL on error and in some cases
 * (UI_process()) -2 if interrupted or in some other way cancelled. When
 * everything is fine, they return 0, a positive value or a non-NULL pointer,
 * all depending on their purpose.
 */

/* Creators and destructo