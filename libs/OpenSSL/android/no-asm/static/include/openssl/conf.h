/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef  HEADER_CONF_H
# define HEADER_CONF_H

# include <openssl/bio.h>
# include <openssl/lhash.h>
# include <openssl/safestack.h>
# include <openssl/e_os2.h>
# include <openssl/ossl_typ.h>
# include <openssl/conferr.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct {
    char *section;
    char *name;
    char *value;
} CONF_VALUE;

DEFINE_STACK_OF(CONF_VALUE)
DEFINE_LHASH_OF(CONF_VALUE);

struct conf_st;
struct conf_method_st;
typedef struct conf_method_st CONF_METHOD;

struct conf_method_st {
    const char *name;
    CONF *(*create) (CONF_METHOD *meth);
    int (*init) (CONF *conf);
    int (*destroy) (CONF *conf);
    int (*destroy_data) (CONF *conf);
    int (*load_bio) (CONF *conf, BIO *bp, long *eline);
    int (*dump) (const CONF *conf, BIO *bp);
    int (*is_number) (const CONF *conf, char c);
    int (*to_int) (const CONF *conf, char c);
    int (*load) (CONF *conf, const char *name, long *eline);
};

/* Module definitions */

typedef struct conf_imodule_st CONF_IMODULE;
typedef struct conf_module_st CONF_MODULE;

DEFINE_STACK_OF(CONF_MODULE)
DEFINE_STACK_OF(CONF_IMODULE)

/* DSO module function typedefs */
typedef int conf_init_func (CONF_IMODULE *md, const CONF *cnf);
typedef void conf_finish_func (CONF_IMODULE *md);

# define CONF_MFLAGS_IGNORE_ERRORS       0x1
# define CONF_MFLAGS_IGNORE_RETURN_CODES 0x2
# define CONF_MFLAGS_SILENT              0x4
# define CONF_MFLAGS_NO_DSO              0x8
# define CONF_MFLAGS_IGNORE_MISSING_FILE 0x10
# define CONF_MFLAGS_DEFAULT_SECTION     0x20

int CONF_set_default_method(CONF_METHOD *meth);
void CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash);
LHASH_OF(CONF_VALUE) *CONF_load(LHASH_OF(CONF_VALUE) *conf, const char *file,
                                long *eline);
# ifndef OPENSSL_NO_STDIO
LHASH_OF(CONF_VALUE) *CONF_load_fp(LHASH_OF(CONF_VALUE) *conf, FILE *fp,
                                   long *eline);
# endif
LHASH_OF(CONF_VALUE) *CONF_load_bio(LHASH_OF(CONF_VALUE) *conf, BIO *bp,
                                    long *eline);
STACK_OF(CONF_VALUE) *CONF_get_section(LHASH_OF(CONF_VALUE) *conf,
                                       const char *section);
char *CONF_get_string(LHASH_OF(CONF_VALUE) *conf, const char *group,
                      const char *name);
long CONF_get_number(LHASH_OF(CONF_VALUE) *conf, const char *grou