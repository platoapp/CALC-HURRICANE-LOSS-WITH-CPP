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
# define SSL3_CK_ADH_DES_64_CBC_SHA              0x0300001A
# define SSL3_CK_ADH_DES_192_CBC_SHA             0x0300001B

/* a bundle of RFC standard cipher names, generated from ssl3_ciphers[] */
# define SSL3_RFC_RSA_NULL_MD5                   "TLS_RSA_WITH_NULL_MD5"
# define SSL3_RFC_RSA_NULL_SHA                   "TLS_RSA_WITH_NULL_SHA"
# define SSL3_RFC_RSA_DES_192_CBC3_SHA           "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
# define SSL3_RFC_DHE_DSS_DES_192_CBC3_SHA       "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
# define SSL3_RFC_DHE_RSA_DES_192_CBC3_SHA       "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
# define SSL3_RFC_ADH_DES_192_CBC_SHA            "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
# define SSL3_RFC_RSA_IDEA_128_SHA               "TLS_RSA_WITH_IDEA_CBC_SHA"
# define SSL3_RFC_RSA_RC4_128_MD5                "TLS_RSA_WITH_RC4_128_MD5"
# define SSL3_RFC_RSA_RC4_128_SHA                "TLS_RSA_WITH_RC4_128_SHA"
# define SSL3_RFC_ADH_RC4_128_MD5                "TLS_DH_anon_WITH_RC4_128_MD5"

# define SSL3_TXT_RSA_NULL_MD5                   "NULL-MD5"
# define SSL3_TXT_RSA_NULL_SHA                   "NULL-SHA"
# define SSL3_TXT_RSA_RC4_40_MD5                 "EXP-RC4-MD5"
# define SSL3_TXT_RSA_RC4_128_MD5                "RC4-MD5"
# define SSL3_TXT_RSA_RC4_128_SHA                "RC4-SHA"
# define SSL3_TXT_RSA_RC2_40_MD5                 "EXP-RC2-CBC-MD5"
# define SSL3_TXT_RSA_IDEA_128_SHA               "IDEA-CBC-SHA"
# define SSL3_TXT_RSA_DES_40_CBC_SHA             "EXP-DES-CBC-SHA"
# define SSL3_TXT_RSA_DES_64_CBC_SHA             "DES-CBC-SHA"
# define SSL3_TXT_RSA_DES_192_CBC3_SHA           "DES-CBC3-SHA"

# define SSL3_TXT_DH_DSS_DES_40_CBC_SHA          "EXP-DH-DSS-DES-CBC-SHA"
# define SSL3_TXT_DH_DSS_DES_64_CBC_SHA          "DH-DSS-DES-CBC-SHA"
# define SSL3_TXT_DH_DSS_DES_192_CBC3_SHA        "DH-DSS-DES-CBC3-SHA"
# define SSL3_TXT_DH_RSA_DES_40_CBC_SHA          "EXP-DH-RSA-DES-CBC-SHA"
# define SSL3_TXT_DH_RSA_DES_64_CBC_SHA          "DH-RSA-DES-CBC-SHA"
# define SSL3_TXT_DH_RSA_DES_192_CBC3_SHA        "DH-RSA-DES-CBC3-SHA"

# define SSL3_TXT_DHE_DSS_DES_40_CBC_SHA         "EXP-DHE-DSS-DES-CBC-SHA"
# define SSL3_TXT_DHE_DSS_DES_64_CBC_SHA         "DHE-DSS-DES-CBC-SHA"
# define SSL3_TXT_DHE_DSS_DES_192_CBC3_SHA       "DHE-DSS-DES-CBC3-SHA"
# define SSL3_TXT_DHE_RSA_DES_40_CBC_SHA         "EXP-DHE-RSA-DES-CBC-SHA"
# define SSL3_TXT_DHE_RSA_DES_64_CBC_SHA         "DHE-RSA-DES-CBC-SHA"
# define SSL3_TXT_DHE_RSA_DES_192_CBC3_SHA       "DHE-RSA-DES-CBC3-SHA"

/*
 * This next block of six "EDH" labels is for backward compatibility with
 * older versions of OpenSSL.  New code should use the six "DHE" labels above
 * instead:
 */
# define SSL3_TXT_EDH_DSS_DES_40_CBC_SHA         "EXP-EDH-DSS-DES-CBC-SHA"
# define SSL3_TXT_EDH_DSS_DES_64_CBC_SHA         "EDH-DSS-DES-CBC-SHA"
# define SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA       "EDH-DSS-DES-CBC3-SHA"
# define SSL3_TXT_EDH_RSA_DES_40_CBC_SHA         "EXP-EDH-RSA-DES-CBC-SHA"
# define SSL3_TXT_EDH_RSA_DES_64_CBC_SHA         "EDH-RSA-DES-CBC-SHA"
# define SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA       "EDH-RSA-DES-CBC3-SHA"

# define SSL3_TXT_ADH_RC4_40_MD5                 "EXP-ADH-RC4-MD5"
# define SSL3_TXT_ADH_RC4_128_MD5                "ADH-RC4-MD5"
# define SSL3_TXT_ADH_DES_40_CBC_SHA             "EXP-ADH-DES-CBC-SHA"
# define SSL3_TXT_ADH_DES_64_CBC_SHA             "ADH-DES-CBC-SHA"
# define SSL3_TXT_ADH_DES_192_CBC_SHA            "ADH-DES-CBC3-SHA"

# define SSL3_SSL_SESSION_ID_LENGTH              32
# define SSL3_MAX_SSL_SESSION_ID_LENGTH          32

# define SSL3_MASTER_SECRET_SIZE                 48
# define SSL3_RANDOM_SIZE                        32
# define SSL3_SESSION_ID_SIZE                    32
# define SSL3_RT_HEADER_LENGTH                   5

# define SSL3_HM_HEADER_LENGTH                  4

# ifndef SSL3_ALIGN_PAYLOAD
 /*
  * Some will argue that this increases memory footprint, but it's not
  * actually true. Po