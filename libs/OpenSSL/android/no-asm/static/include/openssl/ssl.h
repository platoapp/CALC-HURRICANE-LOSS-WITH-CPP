/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
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
# define SSL_FILETYPE_PEM        X509_FILETYPE_PEM

/*
 * This is needed to stop compilers complaining about the 'struct ssl_st *'
 * function parameters used to prototype callbacks in SSL_CTX.
 */
typedef struct ssl_st *ssl_crock_st;
typedef struct tls_session_ticket_ext_st TLS_SESSION_TICKET_EXT;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_cipher_st SSL_CIPHER;
typedef struct ssl_session_st SSL_SESSION;
typedef struct tls_sigalgs_st TLS_SIGALGS;
typedef struct ssl_conf_ctx_st SSL_CONF_CTX;
typedef struct ssl_comp_st SSL_COMP;

STACK_OF(SSL_CIPHER);
STACK_OF(SSL_COMP);

/* SRTP protection profiles for use with the use_srtp extension (RFC 5764)*/
typedef struct srtp_protection_profile_st {
    const char *name;
    unsigned long id;
} SRTP_PROTECTION_PROFILE;

DEFINE_STACK_OF(SRTP_PROTECTION_PROFILE)

typedef int (*tls_session_ticket_ext_cb_fn)(SSL *s, const unsigned char *data,
                                            int len, void *arg);
typedef int (*tls_session_secret_cb_fn)(SSL *s, void *secret, int *secret_len,
                                        STACK_OF(SSL_CIPHER) *peer_ciphers,
                                        const SSL_CIPHER **cipher, void *arg);

/* Extension context codes */
/* This extension is only allowed in TLS */
#define SSL_EXT_TLS_ONLY                        0x0001
/* This extension is only allowed in DTLS */
#define SSL_EXT_DTLS_ONLY                       0x0002
/* Some extensions may be allowed in DTLS but we don't implement them for it */
#define SSL_EXT_TLS_IMPLEMENTATION_ONLY         0x0004
/* Most extensions are not defined for SSLv3 but EXT_TYPE_renegotiate is */
#define SSL_EXT_SSL3_ALLOWED                    0x0008
/* Extension is only defined for TLS1.2 and below */
#define SSL_EXT_TLS1_2_AND_BELOW_ONLY           0x0010
/* Extension is only defined for TLS1.3 and above */
#define SSL_EXT_TLS1_3_ONLY                     0x0020
/* Ignore this extension during parsing if we are resuming */
#define SSL_EXT_IGNORE_ON_RESUMPTION            0x0040
#define SSL_EXT_CLIENT_HELLO                    0x0080
/* Really means TLS1.2 or below */
#define SSL_EXT_TLS1_2_SERVER_HELLO             0x0100
#define SSL_EXT_TLS1_3_SERVER_HELLO             0x0200
#define SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS     0x0400
#define SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST      0x0800
#define SSL_EXT_TLS1_3_CERTIFICATE              0x1000
#define SSL_EXT_TLS1_3_NEW_SESSION_TICKET       0x2000
#define SSL_EXT_TLS1_3_CERTIFICATE_REQUEST      0x4000

/* Typedefs for handling custom extensions */

typedef int (*custom_ext_add_cb)(SSL *s, unsigned int ext_type,
                                 const unsigned char **out, size_t *outlen,
                                 int *al, void *add_arg);

typedef void (*custom_ext_free_cb)(SSL *s, unsigned int ext_type,
                                   const unsigned char *out, void *add_arg);

typedef int (*custom_ext_parse_cb)(SSL *s, unsigned int ext_type,
                                   const unsigned char *in, size_t inlen,
                                   int *al, void *parse_arg);


typedef int (*SSL_custom_ext_add_cb_ex)(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx,
                                        int *al, void *add_arg);

typedef void (*SSL_custom_ext_free_cb_ex)(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg);

typedef int (*SSL_custom_ext_parse_cb_ex)(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx,
                                          int *al, void *parse_arg);

/* Typedef for verification callback */
typedef int (*SSL_verify_cb)(int preverify_ok, X509_STORE_CTX *x509_ctx);

/*
 * Some values are reserved until OpenSSL 1.2.0 because they were previously
 * included in SSL_OP_ALL in a 1.1.x release.
 *
 * Reserved value (until OpenSSL 1.2.0)                  0x00000001U
 * Reserved value (until OpenSSL 1.2.0)                  0x00000002U
 */
/* Allow initial connection to servers that don't support RI */
# define SSL_OP_LEGACY_SERVER_CONNECT                    0x00000004U

/* Reserved value (until OpenSSL 1.2.0)                  0x00000008U */
# define SSL_OP_TLSEXT_PADDING                           0x00000010U
/* Reserved value (until OpenSSL 1.2.0)                  0x00000020U */
# define SSL_OP_SAFARI_ECDHE_ECDSA_BUG                   0x00000040U
/*
 * Reserved value (until OpenSSL 1.2.0)                  0x00000080U
 * Reserved value (until OpenSSL 1.2.0)                  0x00000100U
 * Reserved value (until OpenSSL 1.2.0)                  0x00000200U
 */

/* In TLSv1.3 allow a non-(ec)dhe based kex_mode */
# define SSL_OP_ALLOW_NO_DHE_KEX                         0x00000400U

/*
 * Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added in
 * OpenSSL 0.9.6d.  Usually (depending on the application protocol) the
 * workaround is not needed.  Unfortunately some broken SSL/TLS
 * implementations cannot handle it at all, which is why we include it in
 * SSL_OP_ALL. Added in 0.9.6e
 */
# define SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS              0x00000800U

/* DTLS options */
# define SSL_OP_NO_QUERY_MTU                             0x00001000U
/* Turn on Cookie Exchange (on relevant for servers) */
# define SSL_OP_COOKIE_EXCHANGE                          0x00002000U
/* Don't use RFC4507 ticket extension */
# define SSL_OP_NO_TICKET                                0x00004000U
# ifndef OPENSSL_NO_DTLS1_METHOD
/* Use Cisco's "speshul" version of DTLS_BAD_VER
 * (only with deprecated DTLSv1_client_method())  */
#  define SSL_OP_CISCO_ANYCONNECT                        0x00008000U
# endif

/* As server, disallow session resumption on renegotiation */
# define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   0x00010000U
/* Don't use compression even if supported */
# define SSL_OP_NO_COMPRESSION                           0x00020000U
/* Permit unsafe legacy renegotiation */
# define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION        0x00040000U
/* Disable encrypt-then-mac */
# define SSL_OP_NO_ENCRYPT_THEN_MAC                      0x00080000U

/*
 * Enable TLSv1.3 Compatibility mode. This is on by default. A future version
 * of OpenSSL may have this disabled by default.
 */
# define SSL_OP_ENABLE_MIDDLEBOX_COMPAT                  0x00100000U

/* Prioritize Chacha20Poly1305 when client does.
 * Modifies SSL_OP_CIPHER_SERVER_PREFERENCE */
# define SSL_OP_PRIORITIZE_CHACHA                        0x00200000U

/*
 * Set on servers to choose the cipher according to the server's preferences
 */
# define SSL_OP_CIPHER_SERVER_PREFERENCE                 0x00400000U
/*
 * If set, a server will allow a client to issue a SSLv3.0 version number as
 * latest version supported in the premaster secret, even when TLSv1.0
 * (version 3.1) was announced in the client hello. Normally this is
 * forbidden to prevent version rollback attacks.
 */
# define SSL_OP_TLS_ROLLBACK_BUG                         0x00800000U

/*
 * Switches off automatic TLSv1.3 anti-replay protection for early data. This
 * is a server-side option only (no effect on the client).
 */
# define SSL_OP_NO_ANTI_REPLAY                           0x01000000U

# define SSL_OP_NO_SSLv3                                 0x02000000U
# define SSL_OP_NO_TLSv1                                 0x04000000U
# define SSL_OP_NO_TLSv1_2                               0x08000000U
# define SSL_OP_NO_TLSv1_1                               0x10000000U
# define SSL_OP_NO_TLSv1_3                               0x20000000U

# define SSL_OP_NO_DTLSv1                                0x04000000U
# define SSL_OP_NO_DTLSv1_2                              0x08000000U

# define SSL_OP_NO_SSL_MASK (SSL_OP_NO_SSLv3|\
        SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2|SSL_OP_NO_TLSv1_3)
# define SSL_OP_NO_DTLS_MASK (SSL_OP_NO_DTLSv1|SSL_OP_NO_DTLSv1_2)

/* Disallow all renegotiation */
# define SSL_OP_NO_RENEGOTIATION                         0x40000000U

/*
 * Make server add server-hello extension from early version of cryptopro
 * draft, when GOST ciphersuite is negotiated. Required for interoperability
 * with CryptoPro CSP 3.x
 */
# define SSL_OP_CRYPTOPRO_TLSEXT_BUG                     0x80000000U

/*
 * SSL_OP_ALL: various bug workarounds that should be rather harmless.
 * This used to be 0x000FFFFFL before 0.9.7.
 * This used to be 0x80000BFFU before 1.1.1.
 */
# define SSL_OP_ALL        (SSL_OP_CRYPTOPRO_TLSEXT_BUG|\
                            SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS|\
                            SSL_OP_LEGACY_SERVER_CONNECT|\
                            SSL_OP_TLSEXT_PADDING|\
                            SSL_OP_SAFARI_ECDHE_ECDSA_BUG)

/* OBSOLETE OPTIONS: retained for compatibility */

/* Removed from OpenSSL 1.1.0. Was 0x00000001L */
/* Related to removed SSLv2. */
# define SSL_OP_MICROSOFT_SESS_ID_BUG                    0x0
/* Removed from OpenSSL 1.1.0. Was 0x00000002L */
/* Related to removed SSLv2. */
# define SSL_OP_NETSCAPE_CHALLENGE_BUG                   0x0
/* Removed from OpenSSL 0.9.8q and 1.0.0c. Was 0x00000008L */
/* Dead forever, see CVE-2010-4180 */
# define SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG         0x0
/* Removed from OpenSSL 1.0.1h and 1.0.2. Was 0x00000010L */
/* Refers to ancient SSLREF and SSLv2. */
# define SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG              0x0
/* Removed from OpenSSL 1.1.0. Was 0x00000020 */
# define SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER               0x0
/* Removed from OpenSSL 0.9.7h and 0.9.8b. Was 0x00000040L */
# define SSL_OP_MSIE_SSLV2_RSA_PADDING                   0x0
/* Removed from OpenSSL 1.1.0. Was 0x00000080 */
/* Ancient SSLeay version. */
# define SSL_OP_SSLEAY_080_CLIENT_DH_BUG                 0x0
/* Removed from OpenSSL 1.1.0. Was 0x00000100L */
# define SSL_OP_TLS_D5_BUG                               0x0
/* Removed from OpenSSL 1.1.0. Was 0x00000200L */
# define SSL_OP_TLS_BLOCK_PADDING_BUG                    0x0
/* Removed from OpenSSL 1.1.0. Was 0x00080000L */
# define SSL_OP_SINGLE_ECDH_USE                          0x0
/* Removed from OpenSSL 1.1.0. Was 0x00100000L */
# define SSL_OP_SINGLE_DH_USE                            0x0
/* Removed from OpenSSL 1.0.1k and 1.0.2. Was 0x00200000L */
# define SSL_OP_EPHEMERAL_RSA                            0x0
/* Removed from OpenSSL 1.1.0. Was 0x01000000L */
# define SSL_OP_NO_SSLv2                                 0x0
/* Removed from OpenSSL 1.0.1. Was 0x08000000L */
# define SSL_OP_PKCS1_CHECK_1                            0x0
/* Removed from OpenSSL 1.0.1. Was 0x10000000L */
# define SSL_OP_PKCS1_CHECK_2                            0x0
/* Removed from OpenSSL 1.1.0. Was 0x20000000L */
# define SSL_OP_NETSCAPE_CA_DN_BUG                       0x0
/* Removed from OpenSSL 1.1.0. Was 0x40000000L */
# define SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG          0x0

/*
 * Allow SSL_write(..., n) to return r with 0 < r < n (i.e. report success
 * when just a single record has been written):
 */
# define SSL_MODE_ENABLE_PARTIAL_WRITE       0x00000001U
/*
 * Make it possible to retry SSL_write() with changed buffer location (buffer
 * contents must stay the same!); this is not the default to avoid the
 * misconception that non-blocking SSL_write() behaves like non-blocking
 * write():
 */
# define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002U
/*
 * Never bother the application with retries if the transport is blocking:
 */
# define SSL_MODE_AUTO_RETRY 0x00000004U
/* Don't attempt to automatically build certificate chain */
# define SSL_MODE_NO_AUTO_CHAIN 0x00000008U
/*
 * Save RAM by releasing read and write buffers when they're empty. (SSL3 and
 * TLS only.) Released buffers are freed.
 */
# define SSL_MODE_RELEASE_BUFFERS 0x00000010U
/*
 * Send the current time in the Random fields of the ClientHello and
 * ServerHello records for compatibility with hypothetical implementations
 * that require it.
 */
# define SSL_MODE_SEND_CLIENTHELLO_TIME 0x00000020U
# define SSL_MODE_SEND_SERVERHELLO_TIME 0x00000040U
/*
 * Send TLS_FALLBACK_SCSV in the ClientHello. To be set only by applications
 * that reconnect with a downgraded protocol version; see
 * draft-ietf-tls-downgrade-scsv-00 for details. DO NOT ENABLE THIS if your
 * application attempts a normal handshake. Only use this in explicit
 * fallback retries, following the guidance in
 * draft-ietf-tls-downgrade-scsv-00.
 */
# define SSL_MODE_SEND_FALLBACK_SCSV 0x00000080U
/*
 * Support Asynchronous operation
 */
# define SSL_MODE_ASYNC 0x00000100U

/*
 * When using DTLS/SCTP, include the terminating zero in the label
 * used for computing the endpoint-pair shared secret. Required for
 * interoperability with implementations having this bug like these
 * older version of OpenSSL:
 * - OpenSSL 1.0.0 series
 * - OpenSSL 1.0.1 series
 * - OpenSSL 1.0.2 series
 * - OpenSSL 1.1.0 series
 * - OpenSSL 1.1.1 and 1.1.1a
 */
# define SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG 0x00000400U

/* Cert related flags */
/*
 * Many implementations ignore some aspects of the TLS standards such as
 * enforcing certificate chain algorithms. When this is set we enforce them.
 */
# define SSL_CERT_FLAG_TLS_STRICT                0x00000001U

/* Suite B modes, takes same values as certificate verify flags */
# define SSL_CERT_FLAG_SUITEB_128_LOS_ONLY       0x10000
/* Suite B 192 bit only mode */
# define SSL_CERT_FLAG_SUITEB_192_LOS            0x20000
/* Suite B 128 bit mode allowing 192 bit algorithms */
# define SSL_CERT_FLAG_SUITEB_128_LOS            0x30000

/* Perform all sorts of protocol violations for testing purposes */
# define SSL_CERT_FLAG_BROKEN_PROTOCOL           0x10000000

/* Flags for building certificate chains */
/* Treat any existing certificates as untrusted CAs */
# define SSL_BUILD_CHAIN_FLAG_UNTRUSTED          0x1
/* Don't include root CA in chain */
# define SSL_BUILD_CHAIN_FLAG_NO_ROOT            0x2
/* Just check certificates already there */
# define SSL_BUILD_CHAIN_FLAG_CHECK              0x4
/* Ignore verification errors */
# define SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR       0x8
/* Clear verification errors from queue */
# define SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR        0x10

/* Flags returned by SSL_check_chain */
/* Certificate can be used with this session */
# define CERT_PKEY_VALID         0x1
/* Certificate can also be used for signing */
# define CERT_PKEY_SIGN          0x2
/* EE certificate signing algorithm OK */
# define CERT_PKEY_EE_SIGNATURE  0x10
/* CA signature algorithms OK */
# define CERT_PKEY_CA_SIGNATURE  0x20
/* EE certificate parameters OK */
# define CERT_PKEY_EE_PARAM      0x40
/* CA certificate parameters OK */
# define CERT_PKEY_CA_PARAM      0x80
/* Signing explicitly allowed as opposed to SHA1 fallback */
# define CERT_PKEY_EXPLICIT_SIGN 0x100
/* Client CA issuer names match (always set for server cert) */
# define CERT_PKEY_ISSUER_NAME   0x200
/* Cert type matches client types (always set for server cert) */
# define CERT_PKEY_CERT_TYPE     0x400
/* Cert chain suitable to Suite B */
# define CERT_PKEY_SUITEB        0x800

# define SSL_CONF_FLAG_CMDLINE           0x1
# define SSL_CONF_FLAG_FILE              0x2
# define SSL_CONF_FLAG_CLIENT            0x4
# define SSL_CONF_FLAG_SERVER            0x8
# define SSL_CONF_FLAG_SHOW_ERRORS       0x10
# define SSL_CONF_FLAG_CERTIFICATE       0x20
# define SSL_CONF_FLAG_REQUIRE_PRIVATE   0x40
/* Configuration value types */
# define SSL_CONF_TYPE_UNKNOWN           0x0
# define SSL_CONF_TYPE_STRING            0x1
# define SSL_CONF_TYPE_FILE              0x2
# define SSL_CONF_TYPE_DIR               0x3
# define SSL_CONF_TYPE_NONE              0x4

/* Maximum length of the application-controlled segment of a a TLSv1.3 cookie */
# define SSL_COOKIE_LENGTH                       4096

/*
 * Note: SSL[_CTX]_set_{options,mode} use |= op on the previous value, they
 * cannot be used to clear bits.
 */

unsigned long SSL_CTX_get_options(const SSL_CTX *ctx);
unsigned long SSL_get_options(const SSL *s);
unsigned long SSL_CTX_clear_options(SSL_CTX *ctx, unsigned long op);
unsigned long SSL_clear_options(SSL *s, unsigned long op);
unsigned long SSL_CTX_set_options(SSL_CTX *ctx, unsigned long op);
unsigned long SSL_set_options(SSL *s, unsigned long op);

# define SSL_CTX_set_mode(ctx,op) \
        SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)
# define SSL_CTX_clear_mode(ctx,op) \
        SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_MODE,(op),NULL)
# define SSL_CTX_get_mode(ctx) \
        SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,0,NULL)
# define SSL_clear_mode(ssl,op) \
        SSL_ctrl((ssl),SSL_CTRL_CLEAR_MODE,(op),NULL)
# define SSL_set_mode(ssl,op) \
        SSL_ctrl((ssl),SSL_CTRL_MODE,(op),NULL)
# define SSL_get_mode(ssl) \
        SSL_ctrl((ssl),SSL_CTRL_MODE,0,NULL)
# define SSL_set_mtu(ssl, mtu) \
        SSL_ctrl((ssl),SSL_CTRL_SET_MTU,(mtu),NULL)
# define DTLS_set_link_mtu(ssl, mtu) \
        SSL_ctrl((ssl),DTLS_CTRL_SET_LINK_MTU,(mtu),NULL)
# define DTLS_get_link_min_mtu(ssl) \
        SSL_ctrl((ssl),DTLS_CTRL_GET_LINK_MIN_MTU,0,NULL)

# define SSL_get_secure_renegotiation_support(ssl) \
        SSL_ctrl((ssl), SSL_CTRL_GET_RI_SUPPORT, 0, NULL)

# ifndef OPENSSL_NO_HEARTBEATS
#  define SSL_heartbeat(ssl) \
        SSL_ctrl((ssl),SSL_CTRL_DTLS_EXT_SEND_HEARTBEAT,0,NULL)
# endif

# define SSL_CTX_set_cert_flags(ctx,op) \
        SSL_CTX_ctrl((ctx),SSL_CTRL_CERT_FLAGS,(op),NULL)
# define SSL_set_cert_flags(s,op) \
        SSL_ctrl((s),SSL_CTRL_CERT_FLAGS,(op),NULL)
# define SSL_CTX_clear_cert_flags(ctx,op) \
        SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_CERT_FLAGS,(op),NULL)
# define SSL_clear_cert_flags(s,op) \
        SSL_ctrl((s),SSL_CTRL_CLEAR_CERT_FLAGS,(op),NULL)

void SSL_CTX_set_msg_callback(SSL_CTX *ctx,
                              void (*cb) (int write_p, int version,
                                          int content_type, const void *buf,
                                          size_t len, SSL *ssl, void *arg));
void SSL_set_msg_callback(SSL *ssl,
                          void (*cb) (int write_p, int version,
                                      int content_type, const void *buf,
                                      size_t len, SSL *ssl, void *arg));
# define SSL_CTX_set_msg_callback_arg(ctx, arg) SSL_CTX_ctrl((ctx), SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))
# define SSL_set_msg_callback_arg(ssl, arg) SSL_ctrl((ssl), SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))

# define SSL_get_extms_support(s) \
        SSL_ctrl((s),SSL_CTRL_GET_EXTMS_SUPPORT,0,NULL)

# ifndef OPENSSL_NO_SRP

/* see tls_srp.c */
__owur int SSL_SRP_CTX_init(SSL *s);
__owur int SSL_CTX_SRP_CTX_init(SSL_CTX *ctx);
int SSL_SRP_CTX_free(SSL *ctx);
int SSL_CTX_SRP_CTX_free(SSL_CTX *ctx);
__owur int SSL_srp_server_param_with_username(SSL *s, int *ad);
__owur int SRP_Calc_A_param(SSL *s);

# endif

/* 100k max cert list */
# define SSL_MAX_CERT_LIST_DEFAULT 1024*100

# define SSL_SESSION_CACHE_MAX_SIZE_DEFAULT      (1024*20)

/*
 * This callback type is used inside SSL_CTX, SSL, and in the functions that
 * set them. It is used to override the generation of SSL/TLS session IDs in
 * a server. Return value should be zero on an error, non-zero to proceed.
 * Also, callbacks should themselves check if the id they generate is unique
 * otherwise the SSL handshake will fail with an error - callbacks can do
 * this using the 'ssl' value they're passed by;
 * SSL_has_matching_session_id(ssl, id, *id_len) The length value passed in
 * is set at the maximum size the session ID can be. In SSLv3/TLSv1 it is 32
 * bytes. The callback can alter this length to be less if desired. It is
 * also an error for the callback to set the size to zero.
 */
typedef int (*GEN_SESSION_CB) (SSL *ssl, unsigned char *id,
                               unsigned int *id_len);

# define SSL_SESS_CACHE_OFF                      0x0000
# define SSL_SESS_CACHE_CLIENT                   0x0001
# define SSL_SESS_CACHE_SERVER                   0x0002
# define SSL_SESS_CACHE_BOTH     (SSL_SESS_CACHE_CLIENT|SSL_SESS_CACHE_SERVER)
# define SSL_SESS_CACHE_NO_AUTO_CLEAR            0x0080
/* enough comments already ... see SSL_CTX_set_session_cache_mode(3) */
# define SSL_SESS_CACHE_NO_INTERNAL_LOOKUP       0x0100
# define SSL_SESS_CACHE_NO_INTERNAL_STORE        0x0200
# define SSL_SESS_CACHE_NO_INTERNAL \
        (SSL_SESS_CACHE_NO_INTERNAL_LOOKUP|SSL_SESS_CACHE_NO_INTERNAL_STORE)

LHASH_OF(SSL_SESSION) *SSL_CTX_sessions(SSL_CTX *ctx);
# define SSL_CTX_sess_number(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_NUMBER,0,NULL)
# define SSL_CTX_sess_connect(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT,0,NULL)
# define SSL_CTX_sess_connect_good(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT_GOOD,0,NULL)
# define SSL_CTX_sess_connect_renegotiate(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT_RENEGOTIATE,0,NULL)
# define SSL_CTX_sess_accept(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT,0,NULL)
# define SSL_CTX_sess_accept_renegotiate(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT_RENEGOTIATE,0,NULL)
# define SSL_CTX_sess_accept_good(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT_GOOD,0,NULL)
# define SSL_CTX_sess_hits(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_HIT,0,NULL)
# define SSL_CTX_sess_cb_hits(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CB_HIT,0,NULL)
# define SSL_CTX_sess_misses(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_MISSES,0,NULL)
# define SSL_CTX_sess_timeouts(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_TIMEOUTS,0,NULL)
# define SSL_CTX_sess_cache_full(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CACHE_FULL,0,NULL)

void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx,
                             int (*new_session_cb) (struct ssl_st *ssl,
                                                    SSL_SESSION *sess));
int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx)) (struct ssl_st *ssl,
                                              SSL_SESSION *sess);
void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx,
                                void (*remove_session_cb) (struct ssl_ctx_st
                                                           *ctx,
                                                           SSL_SESSION *sess));
void (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx)) (struct ssl_ctx_st *ctx,
                                                  SSL_SESSION *sess);
void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx,
                             SSL_SESSION *(*get_session_cb) (struct ssl_st
                                                             *ssl,
                                                             const unsigned char
                                                             *data, int len,
                                                             int *copy));
SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx)) (struct ssl_st *ssl,
                                                       const unsigned char *data,
                                                       int len, int *copy);
void SSL_CTX_set_info_callback(SSL_CTX *ctx,
                               void (*cb) (const SSL *ssl, int type, int val));
void (*SSL_CTX_get_info_callback(SSL_CTX *ctx)) (const SSL *ssl, int type,
                                                 int val);
void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx,
                                int (*client_cert_cb) (SSL *ssl, X509 **x509,
                                                       EVP_PKEY **pkey));
int (*SSL_CTX_get_client_cert_cb(SSL_CTX *ctx)) (SSL *ssl, X509 **x509,
                                                 EVP_PKEY **pkey);
# ifndef OPENSSL_NO_ENGINE
__owur int SSL_CTX_set_client_cert_engine(SSL_CTX *ctx, ENGINE *e);
# endif
void SSL_CTX_set_cookie_generate_cb(SSL_CTX *ctx,
                                    int (*app_gen_cookie_cb) (SSL *ssl,
                                                              unsigned char
                                                              *cookie,
                                                              unsigned int
                                                              *cookie_len));
void SSL_CTX_set_cookie_verify_cb(SSL_CTX *ctx,
                                  int (*app_verify_cookie_cb) (SSL *ssl,
                                                               const unsigned
                                                               char *cookie,
                                                               unsigned int
                                                               cookie_len));

void SSL_CTX_set_stateless_cookie_generate_cb(
    SSL_CTX *ctx,
    int (*gen_stateless_cookie_cb) (SSL *ssl,
                                    unsigned char *cookie,
                                    size_t *cookie_len));
void SSL_CTX_set_stateless_cookie_verify_cb(
    SSL_CTX *ctx,
    int (*verify_stateless_cookie_cb) (SSL *ssl,
                                       const unsigned char *cookie,
                                       size_t cookie_len));
# ifndef OPENSSL_NO_NEXTPROTONEG

typedef int (*SSL_CTX_npn_advertised_cb_func)(SSL *ssl,
                                              const unsigned char **out,
                                              unsigned int *outlen,
                                              void *arg);
void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s,
                                           SSL_CTX_npn_advertised_cb_func cb,
                                           void *arg);
#  define SSL_CTX_set_npn_advertised_cb SSL_CTX_set_next_protos_advertised_cb

typedef int (*SSL_CTX_npn_select_cb_func)(SSL *s,
                                          unsigned char **out,
                                          unsigned char *outlen,
                                          const unsigned char *in,
                                          unsigned int inlen,
                                          void *arg);
void SSL_CTX_set_next_proto_select_cb(SSL_CTX *s,
                                      SSL_CTX_npn_select_cb_func cb,
                                      void *arg);
#  define SSL_CTX_set_npn_select_cb SSL_CTX_set_next_proto_select_cb

void SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data,
           