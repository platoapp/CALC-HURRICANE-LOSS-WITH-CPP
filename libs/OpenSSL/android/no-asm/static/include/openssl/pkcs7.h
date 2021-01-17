/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PKCS7_H
# define HEADER_PKCS7_H

# include <openssl/asn1.h>
# include <openssl/bio.h>
# include <openssl/e_os2.h>

# include <openssl/symhacks.h>
# include <openssl/ossl_typ.h>
# include <openssl/pkcs7err.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*-
Encryption_ID           DES-CBC
Digest_ID               MD5
Digest_Encryption_ID    rsaEncryption
Key_Encryption_ID       rsaEncryption
*/

typedef struct pkcs7_issuer_and_serial_st {
    X509_NAME *issuer;
    ASN1_INTEGER *serial;
} PKCS7_ISSUER_AND_SERIAL;

typedef struct pkcs7_signer_info_st {
    ASN1_INTEGER *version;      /* version 1 */
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    X509_ALGOR *digest_alg;
    STACK_OF(X509_ATTRIBUTE) *auth_attr; /* [ 0 ] */
    X509_ALGOR *digest_enc_alg;
    ASN1_OCTET_STRING *enc_digest;
    STACK_OF(X509_ATTRIBUTE) *unauth_attr; /* [ 1 ] */
    /* The private key to sign with */
    EVP_PKEY *pkey;
} PKCS7_SIGNER_INFO;

DEFINE_STACK_OF(PKCS7_SIGNER_INFO)

typedef struct pkcs7_recip_info_st {
    ASN1_INTEGER *version;      /* version 0 */
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    X509_ALGOR *key_enc_algor;
    ASN1_OCTET_STRING *enc_key;
    X509 *cert;                 /* get the pub-key from this */
} PKCS7_RECIP_INFO;

DEFINE_STACK_OF(PKCS7_RECIP_INFO)

typedef struct pkcs7_signed_st {
    ASN1_INTEGER *version;      /* version 1 */
    STACK_OF(X509_ALGOR) *md_algs; /* md used */
    STACK_OF(X509) *cert;       /* [ 0 ] */
    STACK_OF(X509_CRL) *crl;    /* [ 1 ] */
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    struct pkcs7_st *contents;
} PKCS7_SIGNED;
/*
 * The above structure is very very similar to PKCS7_SIGN_ENVELOPE. How about
 * merging the two
 */

typedef struct pkcs7_enc_content_st {
    ASN1_OBJECT *content_type;
    X509_ALGOR *algorithm;
    ASN1_OCTET_STRING *enc_data; /* [ 0 ] */
    const EVP_CIPHER *cipher;
} PKCS7_ENC_CONTENT;

typedef struct pkcs7_enveloped_st {
    ASN1_INTEGER *version;      /* version 0 */
    STACK_OF(PKCS7_RECIP_INFO) *recipientinfo;
    PKCS7_ENC_CONTENT *enc_data;
} PKCS7_ENVELOPE;

typedef struct pkcs7_signedandenveloped_st {
    ASN1_INTEGER *version;      /* version 1 */
    STACK_OF(X509_ALGOR) *md_algs; /* md used */
    STACK_OF(X509) *cert;       /* [ 0 ] */
    STACK_OF(X509_CRL) *crl;    /* [ 1 ] */
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    PKCS7_ENC_CONTENT *enc_data;
    STACK_OF(PKCS7_RECIP_INFO) *recipientinfo;
} PKCS7_SIGN_ENVELOPE;

typedef struct pkcs7_digest_st {
    ASN1_INTEGER *version;      /* version 0 */
    X509_ALGOR *md;             /* md used */
    struct pkcs7_st *contents;
    ASN1_OCTET_STRING *digest;
} PKCS7_DIGEST;

typedef struct pkcs7_encrypted_st {
    ASN1_INTEGER *version;      /* version 0 */
    PKCS7_ENC_CONTENT *enc_data;
} PKCS7_ENCRYPT;

typedef struct pkcs7_st {
    /*
     * The following is non NULL if it contains ASN1 encoding of this
     * structure
     */
    unsigned char *asn1;
    long length;
# define PKCS7_S_HEADER  0
# define PKCS7_S_BODY    1
# define PKCS7_S_TAIL    2
    int state;                  /* used during processing */
    int detached;
    ASN1_OBJECT *type;
    /* content as defined by the type */
    /*
     * all encryption/message digests are applied to the 'contents', leaving
     * out the 'type' field.
     */
    union {
        char *ptr;
        /* NID_pkcs7_data */
        ASN1_OCTET_STRING *data;
        /* NID_pkcs7_signed */
        PKCS7_SIGNED *sign;
        /* NID_pkcs7_enveloped */
        PKCS7_ENVELOPE *enveloped;
        /* NID_pkcs7_signedAndEnveloped */
        PKCS7_SIGN_ENVELOPE *signed_and_enveloped;
        /* NID_pkcs7_digest */
        PKCS7_DIGEST *digest;
        /* NID_pkcs7_encrypted */
        PKCS7_ENCRYPT *encrypted;
        /* Anything else */
        ASN1_TYPE *other;
    } d;
} PKCS7;

DEFINE_STACK_OF(PKCS7)

# define PKCS7_OP_SET_DETACHED_SIGNATURE 1
# define PKCS7_OP_GE