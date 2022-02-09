/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SSL_H
# define HEADER_SSL_H

# include <openssl/e_os2.h>
# include <openssl/opensslconf.h>
# include <openssl/comp.h>
# include <openssl/bio.h>
# if OPENSSL_API_COMPAT < 0x10100000L
#  include <openssl/x509.h>
#  include <openssl/crypto.h>
#  include <openssl/buffer.h>
# endif
# include <openssl/lhash.h>
# include <openssl/pem.h>
# include <openssl/hmac.h>
# include <openssl/async.h>

# include <openssl/safestack.h>
# include <openssl/symhacks.h>
# include <openssl/ct.h>
# include <openssl/sslerr.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* OpenSSL version number for ASN.1 encoding of the session information */
/*-
 * Version 0 - initial version
 * Version 1 - added the optional peer certificate
 */
# define SSL_SESSION_ASN1_VERSION 0x0001

# define SSL_MAX_SSL_SESSION_ID_LENGTH           32
# define SSL_MAX_SID_CTX_LENGTH                  32

# define SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES     (512/8)
# define SSL_MAX_KEY_ARG_LENGTH                  8
# define SSL_MAX_MASTER_KEY_LENGTH               48

/* The maximum number of encrypt/decrypt pipelines we can support */
# define SSL_MAX_PIPELINES  32

/* text strings for the ciphers */

/* These are used to specify which ciphers to use and not to use */

# define SSL_TXT_LOW             "LOW"
# define SSL_TXT_MEDIUM          "MEDIUM"
# define SSL_TXT_HIGH            "HIGH"
# define SSL_TXT_FIPS            "FIPS"

# define SSL_TXT_aNULL           "aNULL"
# define SSL_TXT_eNULL           "eNULL"
# define SSL_TXT_NULL            "NULL"

# define SSL_TXT_kRSA            "kRSA"
# define SSL_TXT_kDHr            "kDHr"/* this cipher class has been removed */
# define SSL_TXT_kDHd            "kDHd"/* this cipher class has been removed */
# define SSL_TXT_kDH             "kDH"/* this cipher class has been removed */
# define SSL_TXT_kEDH            "kEDH"/* alias for kDHE */
# define SSL_TXT_kDHE            "kDHE"
# define SSL_TXT_kECDHr          "kECDHr"/* this cipher class has been removed */
# define SSL_TXT_kECDHe          "kECDHe"/* this cipher class has been removed */
# define SSL_TXT_kECDH           "kECDH"/* this cipher class has been removed */
# define SSL_TXT_kEECDH          "kEECDH"/* alias for kECDHE */
# define SSL_TXT_kECDHE          "kECDHE"
# define SSL_TXT_kPSK            "kPSK"
# define SSL_TXT_kRSAPSK         "kRSAPSK"
# define SSL_TXT_kECDHEPSK       "kECDHEPSK"
# define SSL_TXT_kDHEPSK         "kDHEPSK"
# define SSL_TXT_kGOST           "kGOST"
# define SSL_TXT_kSRP            "kSRP"

# define SSL_TXT_aRSA            "aRSA"
# define SSL_TXT_aDSS            "aDSS"
# define SSL_TXT_aDH             "aDH"/* this cipher class has been removed */
# define SSL_TXT_aECDH           "aECDH"/* this cipher class has been removed */
# define SSL_TXT_aECDSA          "aECDSA"
# define SSL_TXT_aPSK            "aPSK"
# define SSL_TXT_aGOST94         "aGOST94"
# define SSL_TXT_aGOST01         "aGOST01"
# define SSL_TXT_aGOST12         "aGOST12"
# define SSL_TXT_aGOST           "aGOST"
# define SSL_TXT_aSRP            "aSRP"

# define SSL_TXT_DSS             "DSS"
# define SSL_TXT_DH              "DH"
# define SSL_TXT_DHE             "DHE"/* same as "kDHE:-ADH" */
# define SSL_TXT_EDH             "EDH"/* alias for DHE */
# define SSL_TXT_ADH             "ADH"
# define SSL_TXT_RSA             "RSA"
# define SSL_TXT_ECDH            "ECDH"
# define SSL_TXT_EECDH           "EECDH"/* alias for ECDHE" */
# define SSL_TXT_ECDHE           "ECDHE"/* same as "kECDHE:-AECDH" */
# define SSL_TXT_AECDH           "AECDH"
# define SSL_TXT_ECDSA           "ECDSA"
# define SSL_TXT_PSK             "PSK"
# define SSL_TXT_SRP             "SRP"

# define SSL_TXT_DES             "DES"
# define SSL_TXT_3DES            "3DES"
# define SSL_TXT_RC4             "RC4"
# define SSL_TXT_RC2             "RC2"
# define SSL_TXT_IDEA            "IDEA"
# define SSL_TXT_SEED            "SEED"
# define SSL_TXT_AES128          "AES128"
# define SSL_TXT_AES256          "AES256"
# define SSL_TXT_AES             "AES"
# define SSL_TXT_AES_GCM         "AESGCM"
# define SSL_TXT_AES_CCM         "AESCCM"
# define SSL_TXT_AES_CCM_8       "AESCCM8"
# define SSL_TXT_CAMELLIA128     "CAMELLIA128"
# define SSL_TXT_CAMELLIA256     "CAMELLIA256"
# define SSL_TXT_CAMELLIA        "CAMELLIA"
# define SSL_TXT_CHACHA20        "CHACHA20"
# define SSL_TXT_GOST            "GOST89"
# define SSL_TXT_ARIA            "ARIA"
# define SSL_TXT_ARIA_GCM        "ARIAGCM"
# define SSL_TXT_ARIA128         "ARIA128"
# define SSL_TXT_ARIA256         "ARIA256"

# define SSL_TXT_MD5             "MD5"
# define SSL_TXT_SHA1            "SHA1"
# define SSL_TXT_SHA             "SHA"/* same as "SHA1" */
# define SSL_TXT_GOST94          "GOST94"
# define SSL_TXT_GOST89MAC       "GOST89MAC"
# define SSL_TXT_GOST12          "GOST12"
# define SSL_TXT_GOST89MAC12     "GOST89MAC12"
# define SSL_TXT_SHA256          "SHA256"
# define SSL_TXT_SHA384          "SHA384"

# define SSL_TXT_SSLV3           "SSLv3"
# define SSL_TXT_TLSV1           "TLSv1"
# define SSL_TXT_TLSV1_1         "TLSv1.1"
# define SSL_TXT_TLSV1_2         "TLSv1.2"

# define SSL_TXT_ALL             "ALL"

/*-
 * COMPLEMENTOF* definitions. These identifiers are used to (de-select)
 * ciphers normally not being used.
 * Example: "RC4" will activate all ciphers using RC4 including ciphers
 * without authentication, which would normally disabled by DEFAULT (due
 * the "!ADH" being part of default). Therefore "RC4:!COMPLEMENTOFDEFAULT"
 * will make sure that it is also disabled in the specific selection.
 * COMPLEMENTOF* identifiers are portable between version, as adjustments
 * to the default cipher setup will also be included here.
 *
 * COMPLEMENTOFDEFAULT does not experience the same special treatment that
 * DEFAULT gets, as only selection is being done and no sorting as needed
 * for DEFAULT.
 */
# define SSL_TXT_CMPALL          "COMPLEMENTOFALL"
# define SSL_TXT_CMPDEF          "COMPLEMENTOFDEFAULT"

/*
 * The following cipher list is used by default. It also is substituted when
 * an application-defined cipher list string starts with 'DEFAULT'.
 * This applies to ciphersuites for TLSv1.2 and below.
 */
# define SSL_DEFAULT_CIPHER_LIST "ALL:!COMPLEMENTOFDEFAULT:!eNULL"
/* This is the default set of TLSv1.3 ciphersuites */
# if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
#  define TLS_DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:" \
                                   "TLS_CHACHA20_POLY1305_SHA256:" \
                                   "TLS_AES_128_GCM_SHA256"
# else
#  define TLS_DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:" \
                                   "TLS_AES_128_GCM_SHA256"
#endif
/*
 * As of OpenSSL 1.0.0, ssl_create_cipher_list() in ssl/ssl_ciph.c always
 * starts with a reasonable order, and all we have to do for DEFAULT is
 * throwing out anonymous and unencrypted ciphersuites! (The latter are not
 * actually enabled by ALL, but "ALL:RSA" would enable some of them.)
 */

/* Used in SSL_set_shutdown()/SSL_get_shutdown(); */
# define SSL_SENT_SHUTDOWN       1
# define SSL_RECEIVED_SHUTDOWN   2

#ifdef __cplusplus
}
#endif

#ifdef  __cplusplus
extern "C" {
#endif

# define SSL_FILETYPE_ASN1       X509_FILETYPE_ASN1
# define SSL_FILETYPE_PEM        X509_FILET