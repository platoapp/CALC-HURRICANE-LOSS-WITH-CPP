/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_OPENSSL_TYPES_H
# define HEADER_OPENSSL_TYPES_H

#include <limits.h>

#ifdef  __cplusplus
extern "C" {
#endif

# include <openssl/e_os2.h>

# ifdef NO_ASN1_TYPEDEFS
#  define ASN1_INTEGER            ASN1_STRING
#  define ASN1_ENUMERATED         ASN1_STRING
#  define ASN1_BIT_STRING         ASN1_STRING
#  define ASN1_O