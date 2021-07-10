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
# define         X509_V_ERR_CRL_NOT_YET_VALID                    11
# define         X509_V_ERR_CRL_HAS_EXPIRED                      12
# define         X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD       13
# define         X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD        14
# define         X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD       15
# define         X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD       16
# define         X509_V_ERR_OUT_OF_MEM                           17
# define         X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT          18
# define         X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN            19
# define         X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY    20
# define         X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE      21
# define         X509_V_ERR_CERT_CHAIN_TOO_LONG                  22
# define         X509_V_ERR_CERT_REVOKED                         23
# define         X509_V_ERR_INVALID_CA                           24
# define         X509_V_ERR_PATH_LENGTH_EXCEEDED                 25
# define         X509_V_ERR_INVALID_PURPOSE                      26
# define         X509_V_ERR_CERT_UNTRUSTED                       27
# define         X509_V_ERR_CERT_REJECTED                        28
/* These are 'informational' when looking for issuer cert */
# define         X509_V_ERR_SUBJECT_ISSUER_MISMATCH              29
# define         X509_V_ERR_AKID_SKID_MISMATCH                   30
# define         X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH          31
# define         X509_V_ERR_KEYUSAGE_NO_CERTSIGN                 32
# define         X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER             33
# define         X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION         34
# define         X509_V_ERR_KEYUSAGE_NO_CRL_SIGN                 35
# define         X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION     36
# define         X509_V_ERR_INVALID_NON_CA                       37
# define         X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED           38
# define         X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE        39
# define         X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED       40
# define         X509_V_ERR_INVALID_EXTENSION                    41
# define         X509_V_ERR_INVALID_POLICY_EXTENSION             42
# define         X509_V_ERR_NO_EXPLICIT_POLICY                   43
# define         X509_V_ERR_DIFFERENT_CRL_SCOPE                  44
# define         X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE        45
# define         X509_V_ERR_UNNESTED_RESOURCE                    46
# define         X509_V_ERR_PERMITTED_VIOLATION                  47
# define         X509_V_ERR_EXCLUDED_VIOLATION                   48
# define         X509_V_ERR_SUBTREE_MINMAX                       49
/* The application is not happy */
# define         X509_V_ERR_APPLICATION_VERIFICATION             50
# define         X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE          51
# define         X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX        52
# define         X509_V_ERR_UNSUPPORTED_NAME_SYNTAX              53
# define         X509_V_ERR_CRL_PATH_VALIDATION_ERROR            54
/* Another issuer check debug option */
# define         X509_V_ERR_PATH_LOOP                            55
/* Suite B mode algorithm violation */
# define         X509_V_ERR_SUITE_B_INVALID_VERSION              56
# define         X509_V_ERR_SUITE_B_INVALID_ALGORITHM            57
# define         X509_V_ERR_SUITE_B_INVALID_CURVE                58
# define         X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM  59
# define         X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED              60
# define         X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 61
/* Host, email and IP check errors */
# define         X509_V_ERR_HOSTNAME_MISMATCH                    62
# define         X509_V_ERR_EMAIL_MISMATCH                       63
# define         X509_V_ERR_IP_ADDRESS_MISMATCH                  64
/* DANE TLSA errors */
# define         X509_V_ERR_DANE_NO_MATCH                        65
/* security level err