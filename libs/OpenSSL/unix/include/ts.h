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
TS_STATUS_INFO *TS_STATUS_INFO_dup(TS_STATUS_INFO *a);

TS_TST_INFO *TS_TST_INFO_new(void);
void TS_TST_INFO_free(TS_TST_INFO *a);
int i2d_TS_TST_INFO(const TS_TST_INFO *a, unsigned char **pp);
TS_TST_INFO *d2i_TS_TST_INFO(TS_TST_INFO **a, const unsigned char **pp,
                             long length);
TS_TST_INFO *TS_TST_INFO_dup(TS_TST_INFO *a);

#ifndef OPENSSL_NO_STDIO
TS_TST_INFO *d2i_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO **a);
int i2d_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO *a);
#endif
TS_TST_INFO *d2i_TS_TST_INFO_bio(BIO *bio, TS_TST_INFO **a);
int i2d_TS_TST_INFO_bio(BIO *bio, TS_TST_INFO *a);

TS_ACCURACY *TS_ACCURACY_new(void);
void TS_ACCURACY_free(TS_ACCURACY *a);
int i2d_TS_ACCURACY(const TS_ACCURACY *a, unsigned char **pp);
TS_ACCURACY *d2i_TS_ACCURACY(TS_ACCURACY **a, const unsigned char **pp,
                             long length);
TS_ACCURACY *TS_ACCURACY_dup(TS_ACCURACY *a);

ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_new(void);
void ESS_ISSUER_SERIAL_free(ESS_ISSUER_SERIAL *a);
int i2d_ESS_ISSUER_SERIAL(const ESS_ISSUER_SERIAL *a, unsigned char **pp);
ESS_ISSUER_SERIAL *d2i_ESS_ISSUER_SERIAL(ESS_ISSUER_SERIAL **a,
                                         const unsigned char **pp,
                                         long length);
ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_dup(ESS_ISSUER_SERIAL *a);

ESS_CERT_ID *ESS_CERT_ID_new(void);
void ESS_CERT_ID_free(ESS_CERT_ID *a);
int i2d_ESS_CERT_ID(const ESS_CERT_ID *a, unsigned char **pp);
ESS_CERT_ID *d2i_ESS_CERT_ID(ESS_CERT_ID **a, const unsigned char **pp,
                             long length);
ESS_CERT_ID *ESS_CERT_ID_dup(ESS_CERT_ID *a);

ESS_SIGNING_CERT *ESS_SIGNING_CERT_new(void);
void ESS_SIGNING_CERT_free(ESS_SIGNING_CERT *a);
int i2d_ESS_SIGNING_CERT(const ESS_SIGNING_CERT *a, unsigned char **pp);
ESS_SIGNING_CERT *d2i_ESS_SIGNING_CERT(ESS_SIGNING_CERT **a,
                                       const unsigned char **pp, long length);
ESS_SIGNING_CERT *ESS_SIGNING_CERT_dup(ESS_SIGNING_CERT *a);

ESS_CERT_ID_V2 *ESS_CERT_ID_V2_new(void);
void ESS_CERT_ID_V2_free(ESS_CERT_ID_V2 *a);
int i2d_ESS_CERT_ID_V2(const ESS_CERT_ID_V2 *a, unsigned char **pp);
ESS_CERT_ID_V2 *d2i_ESS_CERT_ID_V2(ESS_CERT_ID_V2 **a,
                                   const unsigned char **pp, long length);
ESS_CERT_ID_V2 *ESS_CERT_ID_V2_dup(ESS_CERT_ID_V2 *a);

ESS_SIGNING_CERT_V2 *ESS_SIGNING_CERT_V2_new(void);
void ESS_SIGNING_CERT_V2_free(ESS_SIGNING_CERT_V2 *a);
int i2d_ESS_SIGNING_CERT_V2(const ESS_SIGNING_CERT_V2 *a, unsigned char **pp);
ESS_SIGNING_CERT_V2 *d2i_ESS_SIGNING_CERT_V2(ESS_SIGNING_CERT_V2 **a,
                                             const unsigned char **pp,
                                             long length);
ESS_SIGNING_CERT_V2 *ESS_SIGNING_CERT_V2_dup(ESS_SIGNING_CERT_V2 *a);

int TS_REQ_set_version(TS_REQ *a, long version);
long TS_REQ_get_version(const TS_REQ *a);

int TS_STATUS_INFO_set_status(TS_STATUS_INFO *a, int i);
const ASN1_INTEGER *TS_STATUS_INFO_get0_status(const TS_STATUS_INFO *a);

const STACK_OF(ASN1_UTF8STRING) *
TS_STATUS_INFO_get0_text(const TS_STATUS_INFO *a);

const ASN1_BIT_STRING *
TS_STATUS_INFO_get0_failure_info(const TS_STATUS_INFO *a);

int TS_REQ_set_msg_imprint(TS_REQ *a, TS_MSG_IMPRINT *msg_imprint);
TS_MSG_IMPRINT *TS_REQ_get_msg_imprint(TS_REQ *a);

int TS_MSG_IMPRINT_set_algo(TS_MSG_IMPRINT *a, X509_ALGOR *alg);
X509_ALGOR *TS_MSG_IMPRINT_get_algo(TS_MSG_IMPRINT *a);

int TS_MSG_IMPRINT_set_msg(TS_MSG_IMPRINT *a, unsigned char *d, int len);
ASN1_OCTET_STRING *TS_MSG_IMPRINT_get_msg(TS_MSG_IMPRINT *a);

int TS_REQ_set_policy_id(TS_REQ *a, const ASN1_OBJECT *policy);
ASN1_OBJECT *TS_REQ_get_policy_id(TS_REQ *a);

int TS_REQ_set_nonce(TS_REQ *a, const ASN1_INTEGER *nonce);
const ASN1_INTEGER *TS_REQ_get_nonce(const TS_REQ *a);

int TS_REQ_set_cert_req(TS_REQ *a, int cert_req);
int TS_REQ_get_cert_req(const TS_REQ *a);

STACK_OF(X509_EXTENSION) *TS_REQ_get_exts(TS_REQ *a);
void TS_REQ_ext_free(TS_REQ *a);
int TS_REQ_get_ext_count(TS_REQ *a);
int TS_REQ_get_ext_by_NID(TS_REQ *a, int nid, int lastpos);
int TS_REQ_get_ext_by_OBJ(TS_REQ *a, const ASN1_OBJECT *obj, int lastpos);
int TS_REQ_get_ext_by_critical(TS_REQ *a, int crit, int lastpos);
X509_EXTENSION *TS_REQ_get_ext(TS_REQ *a, int loc);
X509_EXTENSION *TS_REQ_delete_ext(TS_REQ *a, int loc);
int TS_REQ_add_ext(TS_REQ *a, X509_EXTENSION *ex, int loc);
void *TS_REQ_get_ext_d2i(TS_REQ *a, int nid, int *crit, int *idx);

/* Function declarations for TS_REQ defined in ts/ts_req_print.c */

int TS_REQ_print_bio(BIO *bio, TS_REQ *a);

/* Function declarations for TS_RESP defined in ts/ts_resp_utils.c */

int TS_RESP_set_status_info(TS_RESP *a, TS_STATUS_INFO *info);
TS_STATUS_INFO *TS_RESP_get_status_info(TS_RESP *a);

/* Caller loses ownership of PKCS7 and TS_TST_INFO objects. */
void TS_RESP_set_tst_info(TS_RESP *a, PKCS7 *p7, TS_TST_INFO *tst_info);
PKCS7 *TS_RESP_get_token(TS_RESP *a);
TS_TST_INFO *TS_RESP_get_tst_info(TS_RESP *a);

int TS_TST_INFO_set_version(TS_TST_INFO *a, long version);
long TS_TST_INFO_get_version(const TS_TST_INFO *a);

int TS_TST_INFO_set_policy_id(TS_TST_INFO *a, ASN1_OBJECT *policy_id);
ASN1_OBJECT *TS_TST_INFO_get_policy_id(TS_TST_INFO *a);

int TS_TST_INFO_set_msg_imprint(TS_TST_INFO *a, TS_MSG_IMPRINT *msg_imprint);
TS_MSG_IMPRINT *TS_TST_INFO_get_msg_imprint(TS_TST_INFO *a);

int TS_TST_INFO_set_serial(TS_TST_INFO *a, const ASN1_INTEGER *serial);
const ASN1_INTEGER *TS_TST_INFO_get_serial(const TS_TST_INFO *a);

int TS_TST_INFO_set_time(TS_TST_INFO *a, const ASN1_GENERALIZEDTIME *gtime);
const ASN1_GENERALIZEDTIME *TS_TST_INFO_get_time(const TS_TST_INFO *a);

int TS_TST_INFO_set_accuracy(TS_TST_INFO *a, TS_ACCURACY *accuracy);
TS_ACCURACY *TS_TST_INFO_get_accuracy(TS_TST_INFO *a);

int TS_ACCURACY_set_seconds(TS_ACCURACY *a, const ASN1_INTEGER *seconds);
const ASN1_INTEGER *TS_ACCURACY_get_seconds(const TS_ACCURACY *a);

int TS_ACCURACY_set_millis(TS_ACCURACY *a, const ASN1_INTEGER *millis);
const 