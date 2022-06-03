/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_TLS1_H
# define HEADER_TLS1_H

# include <openssl/buffer.h>
# include <openssl/x509.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Default security level if not overridden at config time */
# ifndef OPENSSL_TLS_SECURITY_LEVEL
#  define OPENSSL_TLS_SECURITY_LEVEL 1
# endif

# define TLS1_VERSION                    0x0301
# define TLS1_1_VERSION         