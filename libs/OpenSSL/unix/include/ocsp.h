
/*
 * Copyright 2000-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_OCSP_H
# define HEADER_OCSP_H

#include <openssl/opensslconf.h>

/*
 * These definitions are outside the OPENSSL_NO_OCSP guard because although for
 * historical reasons they have OCSP_* names, they can actually be used
 * independently of OCSP. E.g. see RFC5280
 */
/*-
 *   CRLReason ::= ENUMERATED {
 *        unspecified             (0),
 *        keyCompromise           (1),
 *        cACompromise            (2),
 *        affiliationChanged      (3),
 *        superseded              (4),
 *        cessationOfOperation    (5),
 *        certificateHold         (6),
 *        removeFromCRL           (8) }
 */
#  define OCSP_REVOKED_STATUS_NOSTATUS               -1
#  define OCSP_REVOKED_STATUS_UNSPECIFIED             0
#  define OCSP_REVOKED_STATUS_KEYCOMPROMISE           1
#  define OCSP_REVOKED_STATUS_CACOMPROMISE            2
#  define OCSP_REVOKED_STATUS_AFFILIATIONCHANGED      3
#  define OCSP_REVOKED_STATUS_SUPERSEDED              4
#  define OCSP_REVOKED_STATUS_CESSATIONOFOPERATION    5
#  define OCSP_REVOKED_STATUS_CERTIFICATEHOLD         6
#  define OCSP_REVOKED_STATUS_REMOVEFROMCRL           8


# ifndef OPENSSL_NO_OCSP

#  include <openssl/ossl_typ.h>
#  include <openssl/x509.h>
#  include <openssl/x509v3.h>
#  include <openssl/safestack.h>
#  include <openssl/ocsperr.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Various flags and values */

#  define OCSP_DEFAULT_NONCE_LENGTH       16