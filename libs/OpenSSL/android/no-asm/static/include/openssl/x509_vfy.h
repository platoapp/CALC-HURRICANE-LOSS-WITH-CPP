/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_X509_VFY_H
# define HEADER_X509_VFY_H

/*
 * Protect against recursion, x509.h and x509_vfy.h each include the other.
 */
# ifndef HEADER_X509_H
#  include <openssl/x509.h>
# endif

# include <openssl/opensslconf.h>
# include <openssl/lhash.h>
# include <openssl/bio.h>
# include <openssl/crypto.h>
# include <openssl/symhacks.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*-
SSL_CTX -> X509_STORE
                -> X509_LOOKUP
                        ->X509_LOOKUP_METHOD
                -> X509_LOOKUP
                        ->X509_LOOKUP_METHOD

SSL     -> X509_STORE_CTX
                ->X509_STORE

The X509_STORE holds the tables etc for verification stuff.
A X509_STORE_CTX is used while validating a single certificate.
The X509_STORE has X509_LOOKUPs for looking up certs.
The X509_STORE then calls a function to actually verify the
certificate chain.
*/

typedef enum {
    X509_LU_NONE = 0,
    X509_LU_X509, X509_LU_CRL
} X509_LOOKUP_TYPE;

#if OPENSSL_API_COMPAT < 0x10100000L
#define X509_LU_RETRY   -1
#define X509_LU_FAIL    0
#endif

DEFINE_STACK_OF(X509_LOOKUP)
DEFINE_STACK_OF(X509_OBJECT)
DEFINE_STACK_OF(X509_VERIFY_PARAM)

int X509_STORE_set_depth(X509_STORE *store, int depth);

typedef int (*X509_STORE_CTX_verify_cb)(int, X509_STORE_CTX *);
typedef int (*X509_STORE_CTX_verify_fn)(X509_STORE_CTX *);
typedef int (*X509_STORE_CTX_get_issuer_fn)(X509 **issuer,
                                            X509_STORE_CTX *ctx, X509 *x);
typedef int (*X509_STORE_CTX_check_issued_fn)(X509_STORE_CTX *ctx,
                                              X509 *x, X509 *issuer);
typedef int (*X509_STORE_CTX_check_revocation_fn)(X509_STORE_CTX *ctx);
typedef int (*X509_STORE_CTX_get_crl_fn)(X509_STORE_CTX *ctx,
                                         X509_CRL **crl, X509 *x);
typedef int (*X509_STORE_CTX_check_crl_fn)(X509_STORE_CTX *ctx, X509_CRL *crl);
typedef int (*X509_STORE_CTX_cert_crl_fn)(X509_STORE_CTX *ctx,
                                          X509_CRL *crl, X509 *x);
typedef int (*X509_STORE_CTX_check_policy_fn)(X509_STORE_CTX *ctx);
typedef STACK_OF(X509) *(*X509_STORE_CTX_lookup_certs_fn)(X509_STORE_CTX *ctx,
                                                          X509_NAME *nm);
typedef STACK_OF(X509_CRL) *(*X509_STORE_CTX_lookup_crls_fn)(X509_STORE_CTX *ctx,
                                                             X509_NAME *nm);
typedef int (*X509_STORE_CTX_cleanup_fn)(X509_STORE_CTX *ctx);


void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx, int depth);

# define X509_STORE_CTX_set_app_data(ctx,data) \
        X509_STORE_CTX_set_ex_data(ctx,0,data)
# define X509_STORE_CTX_get_app_data(ctx) \
        X509_STORE_CTX_get_ex_data(ctx,0)

# define X509_L_FILE_LOAD        1
# define X509_L_ADD_DIR          2

# define X509_LOOKUP_load_file(x,name,type) \
                X509_LOOKUP_ctrl((x),X509_L_FILE_LOAD,(name),(long)(type),NULL)

# define X509_LOOKUP_add_dir(x,name,type) \
                X509_LOOKUP_ctrl((x),X509_L_ADD_DIR,(name),(long)(type),NULL)

# define         X509_V_OK                                       0
# define         X509_V_ERR_UNSPECIFIED                          1
# define         X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT            2
# define         X509_V_ERR_UNABLE_TO_GET_CRL                    3
# define         X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE     4
# define         X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE      5
# define         X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY   6
# define         X509_V_ERR_CERT_SIGNATURE_FAILURE               7
# define         X509_V_ERR_CRL_SIGNATURE_FAILURE                8
# define         X509_V_ERR_CERT_NOT_YET_VALID                   9
# define         X509_V_ERR_CERT_HAS_EXPIRED                     10
# define         X509_V_ERR_CRL_NOT_YET_VALID             