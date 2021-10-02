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

# define static_ASN1_SEQUENCE_END_name(stname, tname) \
        ;\
        static_ASN1_ITEM_start(tname) \
                ASN1_ITYPE_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)

# define ASN1_NDEF_SEQUENCE(tname) \
        ASN1_SEQUENCE(tname)

# define ASN1_NDEF_SEQUENCE_cb(tname, cb) \
        ASN1_SEQUENCE_cb(tname, cb)

# define ASN1_SEQUENCE_cb(tname, cb) \
        static const ASN1_AUX tname##_aux = {NULL, 0, 0, 0, cb, 0}; \
        ASN1_SEQUENCE(tname)

# define ASN1_BROKEN_SEQUENCE(tname) \
        static const ASN1_AUX tname##_aux = {NULL, ASN1_AFLG_BROKEN, 0, 0, 0, 0}; \
        ASN1_SEQUENCE(tname)

# define ASN1_SEQUENCE_ref(tname, cb) \
        static const ASN1_AUX tname##_aux = {NULL, ASN1_AFLG_REFCOUNT, offsetof(tname, references), offsetof(tname, lock), cb, 0}; \
        ASN1_SEQUENCE(tname)

# define ASN1_SEQUENCE_enc(tname, enc, cb) \
        static const ASN1_AUX tname##_aux = {NULL, ASN1_AFLG_ENCODING, 0, 0, cb, offsetof(tname, enc)}; \
        ASN1_SEQUENCE(tname)

# define ASN1_NDEF_SEQUENCE_END(tname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_NDEF_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(tname),\
                #tname \
        ASN1_ITEM_end(tname)
# define static_ASN1_NDEF_SEQUENCE_END(tname) \
        ;\
        static_ASN1_ITEM_start(tname) \
                ASN1_ITYPE_NDEF_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(tname),\
                #tname \
        ASN1_ITEM_end(tname)

# define ASN1_BROKEN_SEQUENCE_END(stname) ASN1_SEQUENCE_END_ref(stname, stname)
# define static_ASN1_BROKEN_SEQUENCE_END(stname) \
        static_ASN1_SEQUENCE_END_ref(stname, stname)

# define ASN1_SEQUENCE_END_enc(stname, tname) ASN1_SEQUENCE_END_ref(stname, tname)

# define ASN1_SEQUENCE_END_cb(stname, tname) ASN1_SEQUENCE_END_ref(stname, tname)
# define static_ASN1_SEQUENCE_END_cb(stname, tname) static_ASN1_SEQUENCE_END_ref(stname, tname)

# define ASN1_SEQUENCE_END_ref(stname, tname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #tname \
        ASN1_ITEM_end(tname)
# define static_ASN1_SEQUENCE_END_ref(stname, tname) \
        ;\
        static_ASN1_ITEM_start(tname) \
                ASN1_ITYPE_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)

# define ASN1_NDEF_SEQUENCE_END_cb(stname, tname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_NDEF_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)

/*-
 * This pair helps declare a CHOICE type. We can do:
 *
 *      ASN1_CHOICE(chname) = {
 *              ... CHOICE options ...
 *      ASN1_CHOICE_END(chname)
 *
 *      This will produce an ASN1_ITEM called chname_it
 *      for a structure called chname. The structure
 *      definition must look like this:
 *      typedef struct {
 *              int type;
 *              union {
 *                      ASN1_SOMETHING *opt1;
 *                      ASN1_SOMEOTHER *opt2;
 *              } value;
 *      } chname;
 *
 *      the name of the selector must be 'type'.
 *      to use an alternative selector name use the
 *      ASN1_CHOICE_END_selector() version.
 */

# define ASN1_CHOICE(tname) \
        static const ASN1_TEMPLATE tname##_ch_tt[]

# define ASN1_CHOICE_cb(tname, cb) \
        static const ASN1_AUX tname##_aux = {NULL, 0, 0, 0, cb, 0}; \
        ASN1_CHOICE(tname)

# define ASN1_CHOICE_END(stname) ASN1_CHOICE_END_name(stname, stname)

# define static_ASN1_CHOICE_END(stname) static_ASN1_CHOICE_END_name(stname, stname)

# define ASN1_CHOICE_END_name(stname, tname) ASN1_CHOICE_END_selector(stname, tname, type)

# define static_ASN1_CHOICE_END_name(stname, tname) static_ASN1_CHOICE_END_selector(stname, tname, type)

# define ASN1_CHOICE_END_selector(stname, tname, selname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_CHOICE,\
                offsetof(stname,selname) ,\
                tname##_ch_tt,\
                sizeof(tname##_ch_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)

# define static_ASN1_CHOICE_END_selector(stname, tname, selname) \
        ;\
        static_ASN1_ITEM_start(tname) \
                ASN1_ITYPE_CHOICE,\
                offsetof(stname,selname) ,\
                tname##_ch_tt,\
                sizeof(tname##_ch_tt) / sizeof(ASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)

# define ASN1_CHOICE_END_cb(stname, tname, selname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_CHOICE,\
                offsetof(stname,selname) ,\
                tname##_ch_tt,\
                sizeof(tname##_ch_tt) / sizeof(ASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #stname \
        ASN1_ITEM_end(tname)

/* This helps with the template wrapper form of ASN1_ITEM */

# define ASN1_EX_TEMPLATE_TYPE(flags, tag, name, type) { \
        (flags), (tag), 0,\
        #name, ASN1_ITEM_ref(type) }

/* These help with SEQUENCE or CHOICE components */

/* used to declare other types */

# define ASN1_EX_TYPE(flags, tag, stname, field, type) { \
        (flags), (tag), offsetof(stname, field),\
        #field, ASN1_ITEM_ref(type) }

/* implicit and explicit helper macros */

# define ASN1_IMP_EX(stname, field, type, tag, ex) \
         ASN1_EX_TYPE(ASN1_TFLG_IMPLICIT | (ex), tag, stname, field, type)

# define ASN1_EXP_EX(stname, field, type, tag, ex) \
         ASN1_EX_TYPE(ASN1_TFLG_EXPLICIT | (ex), tag, stname, field, type)

/* Any defined by macros: the field used is in the table itself */

# ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION
#  define ASN1_ADB_OBJECT(tblname) { ASN1_TFLG_ADB_OID, -1, 0, #tblname, (const ASN1_ITEM *)&(tblname##_adb) }
#  define ASN1_ADB_INTEGER(tblname) { ASN1_TFLG_ADB_INT, -1, 0, #tblname, (const ASN1_ITEM *)&(tblname##_adb) }
# else
#  define ASN1_ADB_OBJECT(tblname) { ASN1_TFLG_ADB_OID, -1, 0, #tblname, tblname##_adb }
#  define ASN1_ADB_INTEGER(tblname) { ASN1_TFLG_ADB_INT, -1, 0, #tblname, tblname##_adb }
# endif
/* Plain simple type */
# define ASN1_SIMPLE(stname, field, type) ASN1_EX_TYPE(0,0, stname, field, type)
/* Embedded simple type */
# define ASN1_EMBED(stname, field, type) ASN1_EX_TYPE(ASN1_TFLG_EMBED,0, stname, field, type)

/* OPTIONAL simple type */
# define ASN1_OPT(stname, field, type) ASN1_EX_TYPE(ASN1_TFLG_OPTIONAL, 0, stname, field, type)
# define ASN1_OPT_EMBED(stname, field, type) ASN1_EX_TYPE(ASN1_TFLG_OPTIONAL|ASN1_TFLG_EMBED, 0, stname, field, type)

/* IMPLICIT tagged simple type */
# define ASN1_IMP(stname, field, type, tag) ASN1_IMP_EX(stname, field, type, tag, 0)
# define ASN1_IMP_EMBED(stname, field, type, tag) ASN1_IMP_EX(stname, field, type, tag, ASN1_TFLG_EMBED)

/* IMPLIC