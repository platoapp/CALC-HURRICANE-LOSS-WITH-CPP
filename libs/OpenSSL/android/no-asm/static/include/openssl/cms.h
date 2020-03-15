/*
 * Copyright 2008-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CMS_H
# define HEADER_CMS_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_CMS
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include <openssl/cmserr.h>
# ifdef __cplusplus
extern "C" {
# endif

typedef struct CMS_ContentInfo_st CMS_ContentInfo;
typedef struct CMS_SignerInfo_st CMS_SignerInfo;
typedef struct CMS_CertificateChoices CMS_CertificateChoices;
typedef struct CMS_RevocationInfoChoice_st CMS_RevocationInfoChoice;
typedef struct CMS_RecipientInfo_st CMS_RecipientInfo;
typedef struct CMS_ReceiptRequest_st CMS_ReceiptRequest;
typedef struct CMS_Receipt_st CMS_Receipt;
typedef struct CMS_RecipientEncryptedKey_st CMS_RecipientEncryptedKey;
typedef struct CMS_OtherKeyAttribute_st CMS_OtherKeyAttribute;

DEFINE_STACK_OF(CMS_SignerInfo)
DEFINE_STACK_OF(CMS_RecipientEncryptedKey)
DEFINE_STACK_OF(CMS_RecipientInfo)
DEFINE_STACK_OF(CMS_RevocationInfoChoice)
DECLARE_ASN1_FUNCTIONS(CMS_ContentInfo)
DECLARE_ASN1_FUNCTIONS(CMS_ReceiptRequest)
DECLARE_ASN1_PRINT_FUNCTION(CMS_ContentInfo)

# define CMS_SIGNERINFO_ISSUER_SERIAL    0
# define CMS_SIGNERINFO_KEYIDENTIFIER    1

# define CMS_RECIPINFO_NONE              -1
# define CMS_RECIPINFO_TRANS             0
# define CMS_RECIPINFO_AGREE             1
# define CMS_RECIPINFO_KEK               2
# define CMS_RECIPINFO_PASS              3
# define CMS_RECIPINFO_OTHER             4

/* S/MIME related flags */

# define CMS_TEXT                        0x1
# define CMS_NOCERTS                     0x2
# define CMS_NO_CONTENT_VERIFY           0x4
# define CMS_NO_ATTR_VERIFY              0x8
# define CMS_NOSIGS                      \
                        (CMS_NO_CONTENT_VERIFY|CMS_NO_ATTR_VERIFY)
# define CMS_NOINTERN                    0x10
# define CMS_NO_SIGNER_CERT_VERIFY       0x20
# define CMS_NOVERIFY                    0x20
# define CMS_DETACHED                    0x40
# define CMS_BINARY                      0x80
# define CMS_NOATTR                      0x100
# define CMS_NOSMIMECAP                  0x200
# define CMS_NOOLDMIMETYPE               0x400
# define CMS_CRLFEOL                     0x800
# define CMS_STREAM                      0x1000
# define CMS_NOCRL                       0x2000
# define CMS_PARTIAL                     0x4000
# define CMS_REUSE_DIGEST                0x8000
# define CMS_USE_KEYID                   0x10000
# define CMS_DEBUG_DECRYPT               0x20000
# define CMS_KEY_PARAM                   0x40000
# define CMS_ASCIICRLF                   0x80000

const ASN1_OBJECT *CMS_get0_type(const CMS_ContentInfo *cms);

BIO *CMS_dataInit(CMS_ContentInfo *cms, BIO *icont);
int CMS_dataFinal(CMS_ContentInfo *cms, BIO *bio);

ASN1_OCTET_STRING **CMS_get0_content(CMS_ContentInfo *cms);
int CMS_is_detached(CMS_ContentInfo *cms);
int CMS_set_detached(CMS_ContentInfo *cms, int detached);

# ifdef HEADER_PEM_H
DECLARE_PEM_rw_const(CMS, CMS_ContentInfo)
# endif
int CMS_stream(unsigned char ***boundary, CMS_ContentInfo *cms);
CMS_ContentInfo *d2i_CMS_bio(BIO *bp, CMS_ContentInfo **cms);
int i2d_CMS_bio(BIO *bp, CMS_ContentInfo *cms);

BIO *BIO_new_CMS(BIO *out, CMS_ContentInfo *cms);
int i2d_CMS_bio_stream(BIO *out, CMS_ContentInfo *cms, BIO *in, int flags);
int PEM_write_bio_CMS_stream(BIO *out, CMS_ContentInfo *cms, BIO *in,
                             int flags);
CMS_ContentInfo *SMIME_read_CMS(BIO *bio, BIO **bcont);
int SMIME_write_CMS(BIO *bio, CMS_ContentInfo *cms, BIO *data, int flags);

int CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont,
              unsigned int flags);

CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey,
                          STACK_OF(X509) *certs, BIO *data,
                          unsigned int flags);

CMS_ContentInfo *CMS_sign_receipt(CMS_SignerInfo *si,
                                  X509 *signcert, EVP_PKEY *pkey,
                                  STACK_OF(X509) *certs, unsigned int flags);

int CMS_data(CMS_ContentInfo *cms, BIO *out, unsigned int flags);
CMS_ContentInfo *CMS_data_create(BIO *in, unsigned int flags);

int CMS_digest_verify(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
                      unsigned int flags);
CMS_ContentInfo *CMS_digest_create(BIO *in, const EVP_MD *md,
                                   unsigned int flags);

int CMS_EncryptedData_decrypt(CMS_ContentInfo *cms,
                              const unsigned char *key, size_t keylen,
                              BIO *dcont, BIO *out, unsigned int flags);

CMS_ContentInfo *CMS_EncryptedData_encrypt(BIO *in, const EVP_CIPHER *cipher,
                                           const unsigned char *key,
                                           size_t keylen, unsigned int flags);

int CMS_EncryptedData_set1_key(CMS_ContentInfo *cms, const EVP_CIPHER *ciph,
                               const unsigned char *key, size_t keylen);

int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs,
               X509_STORE *store, BIO *dcont, BIO *out, unsigned int flags);

int CMS_verify_receipt(CMS_ContentInfo *rcms, CMS_ContentInfo *ocms,
                       STACK_OF(X509) *certs,
                       X509_STORE *store, unsigned int flags);

STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);

CMS_ContentInfo *CMS_encrypt(STACK_OF(X509) *certs, BIO *in,
                             const EVP_CIPHER *cipher, unsigned int flags);

int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert,
                BIO *dcont, BIO *out, unsigned int flags);

int CMS_decrypt_set1_pkey(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert);
int CMS_decrypt_set1_key(CMS_ContentInfo *cms,
                         unsigned char *key, size_t keylen,
                         const unsigned char *id, size_t idlen);
int CMS_decrypt_set1_password(CMS_ContentInfo *cms,
                              unsigned char *pass, ossl_ssize_t passlen);

STACK_OF(CMS_RecipientInfo) *CMS_get0_RecipientInfos(CMS_ContentInfo *cms);
int CMS_RecipientInfo_type(CMS_RecipientInfo *ri);
EVP_PKEY_CTX *CMS_RecipientInfo_get0_pkey_ctx(CMS_RecipientInfo *ri);
CMS_ContentInfo *CMS_EnvelopedData_create(const EVP_CIPHER *cipher);
CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms,
                                           X509 *recip, unsigned int fla