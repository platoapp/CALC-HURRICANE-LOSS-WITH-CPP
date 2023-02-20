/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_TS_H
# define HEADER_TS_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_TS
# include <openssl/symhacks.h>
# include <openssl/buffer.h>
# include <openssl/evp.h>
# include <openssl/bio.h>
# include <openssl/asn1.h>
# include <openssl/safestack.h>
# include <openssl/rsa.h>
# include <openssl/dsa.h>
# include <openssl/dh.h>
# include <openssl/tserr.h>
# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/x509.h>
# include <openssl/x509v3.h>

typedef struct TS_msg_imprint_st TS_MSG_IMPRINT;
typedef struct TS_req_st TS_REQ;
typedef struct TS_accuracy_st TS_ACCURACY;
typedef struct TS_tst_info_st TS_TST_INFO;

/* Possible values for status. */
# define TS_STATUS_GRANTED                       0
# define TS_STATUS_GRANTED_WITH_MODS             1
# define TS_STATUS_REJECTION                     2
# define TS_STATUS_WAITING                       3
# define TS_STATUS_REVOCATION_WARNING            4
# define TS_STATUS_REVOCATION_NOTIFICATION       5

/* Possible values for failure_info. */
# define TS_INFO_BAD_ALG                 0
# define TS_INFO_BAD_REQUEST             2
# define TS_INFO_BAD_DATA_FORMAT         5
# define TS_INFO_TIME_NOT_AVAILABLE      14
# define TS_INFO_UNACCEPTED_POLICY       15
# define TS_INFO_UNACCEPTED_EXTENSION    16
# define TS_INFO_ADD_INFO_NOT_AVAILABLE  17
# define TS_INFO_SYSTEM_FAILURE          25


typedef struct TS_status_info_st TS_STATUS_INFO;
typedef struct ESS_issuer_serial ESS_ISSUER_SERIAL;
typedef struct ESS_cert_id ESS_CERT_ID;
typedef struct ESS_signing_cert ESS_SIGNING_CERT;

DEFINE_STACK_OF(ESS_CERT_ID)

typedef struct ESS_cert_id_v2_st ESS_CERT_ID_V2;
typedef struct ESS_signing_cert_v2_st ESS_SIGNING_CERT_V2;

DEFINE_STACK_OF(ESS_CERT_ID_V2)

typedef struct TS_resp_st TS_RESP;

TS_REQ *TS_REQ_new(void);
void TS_REQ_free(TS_REQ *a);
int i2d_TS_REQ(const TS_REQ *a, unsigned char **pp);
TS_REQ *d2i_TS_REQ(TS_REQ **a, const unsigned char **pp, long length);

TS_REQ *TS_REQ_dup(TS_REQ *a);

#ifndef OPENSSL_NO_STDIO
TS_REQ *d2i_TS_REQ_fp(FILE *fp, TS_REQ **a);
int i2d_TS_REQ_fp(FILE *fp, TS_REQ *a);
#endif
TS_REQ *d2i_TS_REQ_bio(BIO *fp, TS_REQ **a);
int i2d_TS_REQ_bio(BIO *fp, TS_REQ *a);

TS_MSG_IMPRINT *TS_MSG_IMPRINT_new(void);
void TS_MSG_IMPRINT_free(TS_MSG_IMPRINT *a);
int i2d_TS_MSG_IMPRINT(const TS_MSG_IMPRINT *a, unsigned char **pp);
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT(TS_MSG_IMPRINT **a,
                                   const unsigned char **pp, long length);

TS_MSG_IMPRINT *TS_MSG_IMPRINT_dup(TS_MSG_IMPRINT *a);

#ifndef OPENSSL_NO_STDIO
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT **a);
int i2d_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT *a);
#endif
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_bio(BIO *bio, TS_MSG_IMPRINT **a);
int i2d_TS_MSG_IMPRINT_bio(BIO *bio, TS_MSG_IMPRINT *a);

TS_RESP *TS_RESP_new(void);
void TS_RESP_free(TS_RESP *a);
int i2d_TS_RESP(const TS_RESP *a, unsigned char **pp);
TS_RESP *d2i_TS_RESP(TS_RESP **a, const unsigned char **pp, long length);
TS_TST_INFO *PKCS7_to_TS_TST_INFO(PKCS7 *token);
TS_RESP *TS_RESP_dup(TS_RESP *a);

#ifndef OPENSSL_NO_STDIO
TS_RESP *d2i_TS_RESP_fp(FILE *fp, TS_RESP **a);
int i2d_TS_RESP_fp(FILE *fp, TS_RESP *a);
#endif
TS_RESP *d2i_TS_RESP_bio(BIO *bio, TS_RESP **a);
int i2d_TS_RESP_bio(BIO *bio, TS_RESP *a);

TS_STATUS_INFO *TS_STATUS_INFO_new(void);
void TS_STATUS_INFO_free(TS_STATUS_INFO *a);
int i2d_TS_STATUS_INFO(const TS_STATUS_INFO *a, unsigned char **pp);
TS_STATUS_INFO *d2i_TS_STATUS_INFO(TS_STATUS_INFO **a,
                                   const unsigned char **pp, long length);
TS_STATUS_INFO