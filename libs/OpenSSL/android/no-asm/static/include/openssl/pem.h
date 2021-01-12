/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PEM_H
# define HEADER_PEM_H

# include <openssl/e_os2.h>
# include <openssl/bio.h>
# include <openssl/safestack.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/pemerr.h>

#ifdef  __cplusplus
extern "C" {
#endif

# define PEM_BUFSIZE             1024

# define PEM_STRING_X509_OLD     "X509 CERTIFICATE"
# define PEM_STRING_X509         "CERTIFICATE"
# define PEM_STRING_X509_TRUSTED "TRUSTED CERTIFICATE"
# define PEM_STRING_X509_REQ_OLD "NEW CERTIFICATE REQUEST"
# define PEM_STRING_X509_REQ     "CERTIFICATE REQUEST"
# define PEM_STRING_X509_CRL     "X509 CRL"
# define PEM_STRING_EVP_PKEY     "ANY PRIVATE KEY"
# define PEM_STRING_PUBLIC       "PUBLIC KEY"
# define PEM_STRING_RSA          "RSA PRIVATE KEY"
# define PEM_STRING_RSA_PUBLIC   "RSA PUBLIC KEY"
# define PEM_STRING_DSA          "DSA PRIVATE KEY"
# define PEM_STRING_DSA_PUBLIC   "DSA PUBLIC KEY"
# define PEM_STRING_PKCS7        "PKCS7"
# define PEM_STRING_PKCS7_SIGNED "PKCS #7 SIGNED DATA"
# define PEM_STRING_PKCS8        "ENCRYPTED PRIVATE KEY"
# define PEM_STRING_PKCS8INF     "PRIVATE KEY"
# define PEM_STRING_DHPARAMS     "DH PARAMETERS"
# define PEM_STRING_DHXPARAMS    "X9.42 DH PARAMETERS"
# define PEM_STRING_SSL_SESSION  "SSL SESSION PARAMETERS"
# define PEM_STRING_DSAPARAMS    "DSA PARAMETERS"
# define PEM_STRING_ECDSA_PUBLIC "ECDSA PUBLIC KEY"
# define PEM_STRING_ECPARAMETERS "EC PARAMETERS"
# define PEM_STRING_ECPRIVATEKEY "EC PRIVATE KEY"
# define PEM_STRING_PARAMETERS   "PARAMETERS"
# define PEM_STRING_CMS          "CMS"

# define PEM_TYPE_ENCRYPTED      10
# define PEM_TYPE_MIC_ONLY       20
# define PEM_TYPE_MIC_CLEAR      30
# define PEM_TYPE_CLEAR          40

/*
 * These macros make the PEM_read/PEM_write functions easier to maintain and
 * write. Now they are all implemented with either: IMPLEMENT_PEM_rw(...) or
 * IMPLEMENT_PEM_rw_cb(...)
 */

# ifdef OPENSSL_NO_STDIO

#  define IMPLEMENT_PEM_read_fp(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_fp(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_fp_const(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1) /**/
# else

#  define IMPLEMENT_PEM_read_fp(name, type, str, asn1) \
type *PEM_read_##name(FILE *fp, type **x, pem_password_cb *cb, void *u)\
{ \
return PEM_ASN1_read((d2i_of_void *)d2i_##asn1, str,fp,(void **)x,cb,u); \
}

#  define IMPLEMENT_PEM_write_fp(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, type *x) \
{ \
return PEM_ASN1_write((i2d_of_void *)i2d_##asn1,str,fp,x,NULL,NULL,0,NULL,NULL); \
}

#  define IMPLEMENT_PEM_write_fp_const(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, const type *x) \
{ \
return PEM_ASN1_write((i2d_of_void *)i2d_##asn1,str,fp,(void *)x,NULL,NULL,0,NULL,NULL); \
}

#  define IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, type *x, const EVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, \
                  void *u) \
        { \
        return PEM_ASN1_write((i2d_of_void *)i2d_##asn1,str,fp,x,enc,kstr,klen,cb,u); \
        }

#  define IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, type *x, const EVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, \
                  void *u) \
        { \
        return PEM_ASN1_write((i2d_of_void *)i2d_##asn1,str,fp,x,enc,kstr,klen,cb,u); \
        }

# endif

# define IMPLEMENT_PEM_read_bio(name, type, str, asn1) \
type *PEM_read_bio_##name(BIO *bp, type **x, pem_password_cb *cb, void *u)\
{ \
return PEM_ASN1_read_bio((d2i_of_void *)d2i_##asn1, str,bp,(void **)x,cb,u); \
}

# define IMPLEMENT_PEM_write_bio(name, type, str, asn1) \
int PEM_write_bio_##name(BIO *bp, type *x) \
{ \
return