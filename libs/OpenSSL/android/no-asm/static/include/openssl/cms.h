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
# define CMS_DEBUG_DEC