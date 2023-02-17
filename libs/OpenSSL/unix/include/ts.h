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
typedef struct ESS