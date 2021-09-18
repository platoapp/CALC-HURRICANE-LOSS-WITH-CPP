/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ASN1T_H
# define HEADER_ASN1T_H

# include <stddef.h>
# include <openssl/e_os2.h>
# include <openssl/asn1.h>

# ifdef OPENSSL_BUILD_SHLIBCRYPTO
#  undef OPENSSL_EXTERN
#  define OPENSSL_EXTERN OPENSSL_EXPORT
# endif

/* ASN1 template defines, structures and functions */

#ifdef  __cplusplus
extern "C" {
#endif

# ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION

/* Macro to obtain ASN1_ADB pointer from a type (only used internally) */
#  define ASN1_ADB_ptr(iptr) ((const ASN1_ADB *)(iptr))

/* Macros for start and end of ASN1_ITEM definition */

#  define ASN1_ITEM_start(itname) \
        const ASN1_ITEM itname##_it = {

#  define static_ASN1_ITEM_start(itname) \
        static const ASN1_ITEM itname##_it = {

#  define ASN1_ITEM_end(itname)                 \
                };

# else

/* Macro to obtain ASN1_ADB pointer from a type (only used internally) */
#  define ASN1_ADB_ptr(iptr) ((const ASN1_ADB *)((iptr)()))

/* Macros for start and end of ASN1_ITEM definition */

#  define ASN1_ITEM_start(itname) \
        const ASN1_ITEM * itname##_it(void) \
        { \
                static const ASN1_ITEM local_it = {

#  define static_ASN1_ITEM_start(itname) \
        static ASN1_ITEM_start(itname)

#  define ASN1_ITEM_end(itname) \
                }; \
        return &loca