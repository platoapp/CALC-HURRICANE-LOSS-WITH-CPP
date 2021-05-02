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
# define TLS1_1_VERSION                  0x0302
# define TLS1_2_VERSION                  0x0303
# define TLS1_3_VERSION                  0x0304
# define TLS_MAX_VERSION                 TLS1_3_VERSION

/* Special value for method supporting multiple versions */
# define TLS_ANY_VERSION                 0x10000

# define TLS1_VERSION_MAJOR              0x03
# define TLS1_VERSION_MINOR              0x01

# define TLS1_1_VERSION_MAJOR            0x03
# define TLS1_1_VERSION_MINOR            0x02

# define TLS1_2_VERSION_MAJOR            0x03
# define TLS1_2_VERSION_MINOR            0x03

# define TLS1_get_version(s) \
        ((SSL_version(s) >> 8) == TLS1_VERSION_MAJOR ? SSL_version(s) : 0)

# define TLS1_get_client_version(s) \
        ((SSL_client_version(s) >> 8) == TLS1_VERSION_MAJOR ? SSL_client_version(s) : 0)

# define TLS1_AD_DECRYPTION_FAILED       21
# define TLS1_AD_RECORD_OVERFLOW         22
# define TLS1_AD_UNKNOWN_CA              48/* fatal */
# define TLS1_AD_ACCESS_DENIED           49/* fatal */
# define TLS1_AD_DECODE_ERROR            50/* fatal */
# define TLS1_AD_DECRYPT_ERROR           51
# define TLS1_AD_EXPORT_RESTRICTION      60/* fatal */
# define TLS1_AD_PROTOCOL_VERSION        70/* fatal */
# define TLS1_AD_INSUFFICIENT_SECURITY   71/* fatal */
# define TLS1_AD_INTERNAL_ERROR          80/* fatal */
# define TLS1_AD_INAPPROPRIATE_FALLBACK  86/* fatal */
# define TLS1_AD_USER_CANCELLED          90
# define TLS1_AD_NO_RENEGOTIATION        100
/* TLSv1.3 alerts */
# define TLS13_AD_MISSING_EXTENSION      109 /* fatal */
# define TLS13_AD_CERTIFICATE_REQUIRED   116 /* fatal */
/* codes 110-114 are from RFC3546 */
# define TLS1_AD_UNSUPPORTED_EXTENSION   110
# define TLS1_AD_CERTIFICATE_UNOBTAINABLE 111
# define TLS1_AD_UNRECOGNIZED_NAME       112
# define TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE 113
# define TLS1_AD_BAD_CERTIFICATE_HASH_VALUE 114
# define TLS1_AD_UNKNOWN_PSK_IDENTITY    115/* fatal */
# define TLS1_AD_NO_APPLIC