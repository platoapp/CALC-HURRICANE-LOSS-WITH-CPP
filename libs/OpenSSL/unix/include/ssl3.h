/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SSL3_H
# define HEADER_SSL3_H

# include <openssl/comp.h>
# include <openssl/buffer.h>
# include <openssl/evp.h>
# include <openssl/ssl.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Signalling cipher suite value from RFC 5746
 * (TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
 */
# define SSL3_CK_SCSV                            0x030000FF

/*
 * Signalling cipher suite value from draft-ietf-tls-downgrade-scsv-00
 * (TLS_FALLBACK_SCSV)
 */
# define SSL3_CK_FALLBACK_SCSV                   0x03005600

# define SSL3_CK_RSA_NULL_MD5                    0x03000001
# define SSL3_CK_RSA_NULL_SHA                    0x03000002
# define SSL3_CK_RSA_RC4_40_MD5                  0x03000003
# define SSL3_CK_RSA_RC4_128_MD5                 0x03000004
# define SSL3_CK_RSA_RC4_128_SHA                 0x03000005
# define SSL3_CK_RSA_RC2_40_MD5                  0x03000006
# define SSL3_CK_RSA_IDEA_128_SHA                0x03000007
# define SSL3_CK_RSA_DES_40_CBC_SHA              0x03000008
# define SSL3_CK_RSA_DES_64_CBC_SHA              0x03000009
# define SSL3_CK_RSA_DES_192_CBC3_SHA            0x0300000A

# define SSL3_CK_DH_DSS_DES_40_CBC_SHA           0x0300000B
# define SSL3_CK_DH_DSS_DES_64_CBC_SHA           0x0300000C
# define SSL3_CK_DH_DSS_DES_192_CBC3_SHA         0x0300000D
# define SSL3_CK_DH_RSA_DES_40_CBC_SHA           0x0300000E
# define SSL3_CK_DH_RSA_DES_64_CBC_SHA           0x0300000F
# define SSL3_CK_DH_RSA_DES_192_CBC3_SHA         0x03000010

# define SSL3_CK_DHE_DSS_DES_40_CBC_SHA          0x03000011
# define SSL3_CK_EDH_DSS_DES_40_CBC_SHA          SSL3_CK_DHE_DSS_DES_40_CBC_SHA
# define SSL3_CK_DHE_DSS_DES_64_CBC_SHA          0x03000012
# define SSL3_CK_EDH_DSS_DES_64_CBC_SHA          SSL3_CK_DHE_DSS_DES_64_CBC_SHA
# define SSL3_CK_DHE_DSS_DES_192_CBC3_SHA        0x03000013
# define SSL3_CK_EDH_DSS_DES_192_CBC3_SHA        SSL3_CK_DHE_DSS_DES_192_CBC3_SHA
# define SSL3_CK_DHE_RSA_DES_40_CBC_SHA          0x03000014
# define SSL3_CK_EDH_RSA_DES_40_CBC_SHA          SSL3_CK_DHE_RSA_DES_40_CBC_SHA
# define SSL3_CK_DHE_RSA_DES_64_CBC_SHA          0x03000015
# define SSL3_CK_EDH_RSA_DES_64_CBC_SHA          SSL3_CK_DHE_RSA_DES_64_CBC_SHA
# define SSL3_CK_DHE_RSA_DES_192_CBC3_SHA        0x03000016
# define SSL3_CK_EDH_RSA_DES_192_CBC3_SHA        SSL3_CK_DHE_RSA_DES_192_CBC3_SHA

# define SSL3_CK_ADH_RC4_40_MD5                  0x03000017
# define SSL3_CK_ADH_RC4_128_MD5                 0x03000018
# define SSL3_CK_ADH_DES_40_CBC_SHA              0x03000019