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
#  define ASN1_OCTET_STRING       ASN1_STRING
#  define ASN1_PRINTABLESTRING    ASN1_STRING
#  define ASN1_T61STRING          ASN1_STRING
#  define ASN1_IA5STRING          ASN1_STRING
#  define ASN1_UTCTIME            ASN1_STRING
#  define ASN1_GENERALIZEDTIME    ASN1_STRING
#  define ASN1_TIME               ASN1_STRING
#  define ASN1_GENERALSTRING      ASN1_STRING
#  define ASN1_UNIVERSALSTRING    ASN1_STRING
#  define ASN1_BMPSTRING          ASN1_STRING
#  define ASN1_VISIBLESTRING      ASN1_STRING
#  define ASN1_UTF8STRING         ASN1_STRING
#  define ASN1_BOOLEAN            int
#  define ASN1_NULL               int
# else
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN