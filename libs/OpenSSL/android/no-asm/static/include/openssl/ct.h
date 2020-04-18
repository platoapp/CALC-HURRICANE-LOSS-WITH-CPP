/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CT_H
# define HEADER_CT_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_CT
# include <openssl/ossl_typ.h>
# include <openssl/safestack.h>
# include <openssl/x509.h>
# include <openssl/cterr.h>
# ifdef  __cplusplus
extern "C" {
# endif


/* Minimum RSA key size, from RFC6962 */
# define SCT_MIN_RSA_BITS 2048

/* All hashes are SHA256 in v1 of Certificate Transparency */
# define CT_V1_HASHLEN SH