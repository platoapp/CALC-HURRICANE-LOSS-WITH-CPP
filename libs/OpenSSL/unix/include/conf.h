
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
