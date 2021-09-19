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
        return &local_it; \
        }

# endif

/* Macros to aid ASN1 template writing */

# define ASN1_ITEM_TEMPLATE(tname) \
        static const ASN1_TEMPLATE tname##_item_tt

# define ASN1_ITEM_TEMPLATE_END(tname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_PRIMITIVE,\
                -1,\
                &tname##_item_tt,\
                0,\
                NULL,\
                0,\
                #tname \
        ASN1_ITEM_end(tname)
# define static_ASN1_ITEM_TEMPLATE_END(tname) \
        ;\
        static_ASN1_ITEM_start(tname) \
                ASN1_ITYPE_PRIMITIVE,\
                -1,\
                &tname##_item_tt,\
                0,\
                NULL,\
                0,\
                #tname \
        ASN1_ITEM_end(tname)

/* This is a ASN1 type which just embeds a template */

/*-
 * This pair helps declare a SEQUENCE. We can do:
 *
 *      ASN1_SEQUENCE(stname) = {
 *              ... SEQUENCE components ...
 *      } ASN1_SEQUENCE_END(stname)
 *
 *      This will produce an ASN1_ITEM called stname_it
 *      for a structure called stname.
 *
 *      If you want the same structure but a different
 *      name then use:
 *
 *      ASN1_SEQUENCE(itname) = {
 *              ... SEQUENCE components ...
 *      } ASN1_SEQUENCE_END_name(stname, itname)
 *
 *      This will create an item called itname_it using
 *      a structure called stname.
 */

# define ASN1_SEQUENCE(tname) \
        static const ASN1_TEMPLATE tname##_seq_tt[]

# define ASN1_SEQUENCE_END(stname) ASN1_SEQUENCE_END_name(stname, stname)

# define static_ASN1_SEQUENCE_END(stname) static_ASN1_SEQUENCE_END_name(stname, stname)

# define ASN1_SEQUENCE_END_name(stname, tname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #tname \
        ASN1_ITEM_end(tname)

# define 