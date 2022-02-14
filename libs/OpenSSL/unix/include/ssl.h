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
/* Removed from 