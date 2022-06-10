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

#ifndef HEADER_TLS1_H
# define HEADER_TLS1_H

# include <openssl/buffer.h>
# include <openssl/x509.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Default security level if not overridden at config time */
# ifndef OPENSSL_TLS_SECURITY_LEVEL
#  define OPENSSL_TLS_SECURITY_LEVEL 1
# endif

# define TLS1_VERSION                    0x0301
# define TLS1_1_VERSION                  0x0302
# define TLS1_2_VERSION                  0x0303
# define TLS1_3_VERSION                  0x0304
# define TLS_MAX_VERSION                 TLS1_3_VERSION

/* Special value for method supporting multiple versions */
# define TLS_ANY_VERSION                 0x10000

# define TLS1_VERSION_MAJOR              0x03
# define TLS1_VERSION_MINOR              0x01

# define TLS1_1_VERSION_MAJOR            0x03
# define TLS1_1_VERSION_MINOR            0x02

# define TLS1_2_VERSION_MAJOR            0x03
# define TLS1_2_VERSION_MINOR            0x03

# define TLS1_get_version(s) \
        ((SSL_version(s) >> 8) == TLS1_VERSION_MAJOR ? SSL_version(s) : 0)

# define TLS1_get_client_version(s) \
        ((SSL_client_version(s) >> 8) == TLS1_VERSION_MAJOR ? SSL_client_version(s) : 0)

# define TLS1_AD_DECRYPTION_FAILED       21
# define TLS1_AD_RECORD_OVERFLOW         22
# define TLS1_AD_UNKNOWN_CA              48/* fatal */
# define TLS1_AD_ACCESS_DENIED           49/* fatal */
# define TLS1_AD_DECODE_ERROR            50/* fatal */
# define TLS1_AD_DECRYPT_ERROR           51
# define TLS1_AD_EXPORT_RESTRICTION      60/* fatal */
# define TLS1_AD_PROTOCOL_VERSION        70/* fatal */
# define TLS1_AD_INSUFFICIENT_SECURITY   71/* fatal */
# define TLS1_AD_INTERNAL_ERROR          80/* fatal */
# define TLS1_AD_INAPPROPRIATE_FALLBACK  86/* fatal */
# define TLS1_AD_USER_CANCELLED          90
# define TLS1_AD_NO_RENEGOTIATION        100
/* TLSv1.3 alerts */
# define TLS13_AD_MISSING_EXTENSION      109 /* fatal */
# define TLS13_AD_CERTIFICATE_REQUIRED   116 /* fatal */
/* codes 110-114 are from RFC3546 */
# define TLS1_AD_UNSUPPORTED_EXTENSION   110
# define TLS1_AD_CERTIFICATE_UNOBTAINABLE 111
# define TLS1_AD_UNRECOGNIZED_NAME       112
# define TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE 113
# define TLS1_AD_BAD_CERTIFICATE_HASH_VALUE 114
# define TLS1_AD_UNKNOWN_PSK_IDENTITY    115/* fatal */
# define TLS1_AD_NO_APPLICATION_PROTOCOL 120 /* fatal */

/* ExtensionType values from RFC3546 / RFC4366 / RFC6066 */
# define TLSEXT_TYPE_server_name                 0
# define TLSEXT_TYPE_max_fragment_length         1
# define TLSEXT_TYPE_client_certificate_url      2
# define TLSEXT_TYPE_trusted_ca_keys             3
# define TLSEXT_TYPE_truncated_hmac              4
# define TLSEXT_TYPE_status_request              5
/* ExtensionType values from RFC4681 */
# define TLSEXT_TYPE_user_mapping                6
/* ExtensionType values from RFC5878 */
# define TLSEXT_TYPE_client_authz                7
# define TLSEXT_TYPE_server_authz                8
/* ExtensionType values from RFC6091 */
# define TLSEXT_TYPE_cert_type           9

/* ExtensionType values from RFC4492 */
/*
 * Prior to TLSv1.3 the supported_groups extension was known as
 * elliptic_curves
 */
# define TLSEXT_TYPE_supported_groups            10
# define TLSEXT_TYPE_elliptic_curves             TLSEXT_TYPE_supported_groups
# define TLSEXT_TYPE_ec_point_formats            11


/* ExtensionType value from RFC5054 */
# define TLSEXT_TYPE_srp                         12

/* ExtensionType values from RFC5246 */
# define TLSEXT_TYPE_signature_algorithms        13

/* ExtensionType value from RFC5764 */
# define TLSEXT_TYPE_use_srtp    14

/* ExtensionType value from RFC5620 */
# define TLSEXT_TYPE_heartbeat   15

/* ExtensionType value from RFC7301 */
# define TLSEXT_TYPE_application_layer_protocol_negotiation 16

/*
 * Extension type for Certificate Transparency
 * https://tools.ietf.org/html/rfc6962#section-3.3.1
 */
# define TLSEXT_TYPE_signed_certificate_timestamp    18

/*
 * ExtensionType value for TLS padding extension.
 * http://tools.ietf.org/html/draft-agl-tls-padding
 */
# define TLSEXT_TYPE_padding     21

/* ExtensionType value from RFC7366 */
# define TLSEXT_TYPE_encrypt_then_mac    22

/* ExtensionType value from RFC7627 */
# define TLSEXT_TYPE_extended_master_secret      23

/* ExtensionType value from RFC4507 */
# define TLSEXT_TYPE_session_ticket              35

/* As defined for TLS1.3 */
# define TLSEXT_TYPE_psk                         41
# define TLSEXT_TYPE_early_data                  42
# define TLSEXT_TYPE_supported_versions          43
# define TLSEXT_TYPE_cookie                      44
# define TLSEXT_TYPE_psk_kex_modes               45
# define TLSEXT_TYPE_certificate_authorities     47
# define TLSEXT_TYPE_post_handshake_auth         49
# define TLSEXT_TYPE_signature_algorithms_cert   50
# define TLSEXT_TYPE_key_share                   51

/* Temporary extension type */
# define TLSEXT_TYPE_renegotiate                 0xff01

# ifndef OPENSSL_NO_NEXTPROTONEG
/* This is not an IANA defined extension number */
#  define TLSEXT_TYPE_next_proto_neg              13172
# endif

/* NameType value from RFC3546 */
# define TLSEXT_NAMETYPE_host_name 0
/* status request value from RFC3546 */
# define TLSEXT_STATUSTYPE_ocsp 1

/* ECPointFormat values from RFC4492 */
# define TLSEXT_ECPOINTFORMAT_first                      0
# define TLSEXT_ECPOINTFORMAT_uncompressed               0
# define TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime  1
# define TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2  2
# define TLSEXT_ECPOINTFORMAT_last                       2

/* Signature and hash algorithms from RFC5246 */
# define TLSEXT_signature_anonymous                      0
# define TLSEXT_signature_rsa                            1
# define TLSEXT_signature_dsa                            2
# define TLSEXT_signature_ecdsa                          3
# define TLSEXT_signature_gostr34102001                  237
# define TLSEXT_signature_gostr34102012_256              238
# define TLSEXT_signature_gostr34102012_512              239

/* Total number of different signature algorithms */
# define TLSEXT_signature_num                            7

# define TLSEXT_hash_none                                0
# define TLSEXT_hash_md5                                 1
# define TLSEXT_hash_sha1                                2
# define TLSEXT_hash_sha224                              3
# define TLSEXT_hash_sha256                              4
# define TLSEXT_hash_sha384                              5
# define TLSEXT_hash_sha512                              6
# define TLSEXT_hash_gostr3411                           237
# define TLSEXT_hash_gostr34112012_256                   238
# define TLSEXT_hash_gostr34112012_512                   239

/* Total number of different digest algorithms */

# define TLSEXT_hash_num                                 10

/* Flag set for unrecognised algorithms */
# define TLSEXT_nid_unknown                              0x1000000

/* ECC curves */

# define TLSEXT_curve_P_256                              23
# define TLSEXT_curve_P_384                              24

/* OpenSSL value to disable maximum fragment length extension */
# define TLSEXT_max_fragment_length_DISABLED    0
/* Allowed values for max fragment length extension */
# define TLSEXT_max_fragment_length_512         1
# define TLSEXT_max_fragment_length_1024        2
# define TLSEXT_max_fragment_length_2048        3
# define TLSEXT_max_fragment_length_4096        4

int SSL_CTX_set_tlsext_max_fragment_length(SSL_CTX *ctx, uint8_t mode);
int SSL_set_tlsext_max_fragment_length(SSL *ssl, uint8_t mode);

# define TLSEXT_MAXLEN_host_name 255

__owur const char *SSL_get_servername(const SSL *s, const int type);
__owur int SSL_get_servername_type(const SSL *s);
/*
 * SSL_export_keying_material exports a value derived from the master secret,
 * as specified in RFC 5705. It writes |olen| bytes to |out| given a label and
 * optional context. (Since a zero length context is allowed, the |use_context|
 * flag controls whether a context is included.) It returns 1 on success and
 * 0 or -1 otherwise.
 */
__owur int SSL_export_keying_material(SSL *s, unsigned char *out, size_t olen,
                                      const char *label, size_t llen,
                                      const unsigned char *context,
                                      size_t contextlen, int use_context);

/*
 * SSL_export_keying_material_early exports a value derived from the
 * early exporter master secret, as specified in
 * https://tools.ietf.org/html/draft-ietf-tls-tls13-23. It writes
 * |olen| bytes to |out| given a label and optional context. It
 * returns 1 on success and 0 otherwise.
 */
__owur int SSL_export_keying_material_early(SSL *s, unsigned char *out,
                                            size_t olen, const char *label,
                                            size_t llen,
                                            const unsigned char *context,
                                            size_t contextlen);

int SSL_get_peer_signature_type_nid(const SSL *s, int *pnid);
int SSL_get_signature_type_nid(const SSL *s, int *pnid);

int SSL_get_sigalgs(SSL *s, int idx,
                    int *psign, int *phash, int *psignandhash,
                    unsigned char *rsig, unsigned char *rhash);

int SSL_get_shared_sigalgs(SSL *s, int idx,
                           int *psign, int *phash, int *psignandhash,
                           unsigned char *rsig, unsigned char *rhash);

__owur int SSL_check_chain(SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain);

# define SSL_set_tlsext_host_name(s,name) \
        SSL_ctrl(s,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name,\
                (void *)name)

# define SSL_set_tlsext_debug_callback(ssl, cb) \
        SSL_callback_ctrl(ssl,SSL_CTRL_SET_TLSEXT_DEBUG_CB,\
                (void (*)(void))cb)

# define SSL_set_tlsext_debug_arg(ssl, arg) \
        SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_DEBUG_ARG,0,arg)

# define SSL_get_tlsext_status_type(ssl) \
        SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE,0,NULL)

# define SSL_set_tlsext_status_type(ssl, type) \
        SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,type,NULL)

# define SSL_get_tlsext_status_exts(ssl, arg) \
        SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS,0,arg)

# define SSL_set_tlsext_status_exts(ssl, arg) \
        SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS,0,arg)

# define SSL_get_tlsext_status_ids(ssl, arg) \
        SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS,0,arg)

# define SSL_set_tlsext_status_ids(ssl, arg) \
        SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS,0,arg)

# define SSL_get_tlsext_status_ocsp_resp(ssl, arg) \
        SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP,0,arg)

# define SSL_set_tlsext_status_ocsp_resp(ssl, arg, arglen) \
        SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP,arglen,arg)

# define SSL_CTX_set_tlsext_servername_callback(ctx, cb) \
        SSL_CTX_callback_ctrl(ctx,SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,\
                (void (*)(void))cb)

# define SSL_TLSEXT_ERR_OK 0
# define SSL_TLSEXT_ERR_ALERT_WARNING 1
# define SSL_TLSEXT_ERR_ALERT_FATAL 2
# define SSL_TLSEXT_ERR_NOACK 3

# define SSL_CTX_set_tlsext_servername_arg(ctx, arg) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG,0,arg)

# define SSL_CTX_get_tlsext_ticket_keys(ctx, keys, keylen) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_TLSEXT_TICKET_KEYS,keylen,keys)
# define SSL_CTX_set_tlsext_ticket_keys(ctx, keys, keylen) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TLSEXT_TICKET_KEYS,keylen,keys)

# define SSL_CTX_get_tlsext_status_cb(ssl, cb) \
        SSL_CTX_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB,0,(void *)cb)
# define SSL_CTX_set_tlsext_status_cb(ssl, cb) \
        SSL_CTX_callback_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB,\
                (void (*)(void))cb)

# define SSL_CTX_get_tlsext_status_arg(ssl, arg) \
        SSL_CTX_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG,0,arg)
# define SSL_CTX_set_tlsext_status_arg(ssl, arg) \
        SSL_CTX_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG,0,arg)

# define SSL_CTX_set_tlsext_status_type(ssl, type) \
        SSL_CTX_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,type,NULL)

# define SSL_CTX_get_tlsext_status_type(ssl) \
        SSL_CTX_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE,0,NULL)

# define SSL_CTX_set_tlsext_ticket_key_cb(ssl, cb) \
        SSL_CTX_callback_ctrl(ssl,SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB,\
                (void (*)(void))cb)

# ifndef OPENSSL_NO_HEARTBEATS
#  define SSL_DTLSEXT_HB_ENABLED                   0x01
#  define SSL_DTLSEXT_HB_DONT_SEND_REQUESTS        0x02
#  define SSL_DTLSEXT_HB_DONT_RECV_REQUESTS        0x04
#  define SSL_get_dtlsext_heartbeat_pending(ssl) \
        SSL_ctrl(ssl,SSL_CTRL_GET_DTLS_EXT_HEARTBEAT_PENDING,0,NULL)
#  define SSL_set_dtlsext_heartbeat_no_requests(ssl, arg) \
        SSL_ctrl(ssl,SSL_CTRL_SET_DTLS_EXT_HEARTBEAT_NO_REQUESTS,arg,NULL)

#  if OPENSSL_API_COMPAT < 0x10100000L
#   define SSL_CTRL_TLS_EXT_SEND_HEARTBEAT \
        SSL_CTRL_DTLS_EXT_SEND_HEARTBEAT
#   define SSL_CTRL_GET_TLS_EXT_HEARTBEAT_PENDING \
        SSL_CTRL_GET_DTLS_EXT_HEARTBEAT_PENDING
#   define SSL_CTRL_SET_TLS_EXT_HEARTBEAT_NO_REQUESTS \
        SSL_CTRL_SET_DTLS_EXT_HEARTBEAT_NO_REQUESTS
#   define SSL_TLSEXT_HB_ENABLED \
        SSL_DTLSEXT_HB_ENABLED
#   define SSL_TLSEXT_HB_DONT_SEND_REQUESTS \
        SSL_DTLSEXT_HB_DONT_SEND_REQUESTS
#   define SSL_TLSEXT_HB_DONT_RECV_REQUESTS \
        SSL_DTLSEXT_HB_DONT_RECV_REQUESTS
#   define SSL_get_tlsext_heartbeat_pending(ssl) \
        SSL_get_dtlsext_heartbeat_pending(ssl)
#   define SSL_set_tlsext_heartbeat_no_requests(ssl, arg) \
        SSL_set_dtlsext_heartbeat_no_requests(ssl,arg)
#  endif
# endif

/* PSK ciphersuites from 4279 */
# define TLS1_CK_PSK_WITH_RC4_128_SHA                    0x0300008A
# define TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA               0x0300008B
# define TLS1_CK_PSK_WITH_AES_128_CBC_SHA                0x0300008C
# define TLS1_CK_PSK_WITH_AES_256_CBC_SHA                0x0300008D
# define TLS1_CK_DHE_PSK_WITH_RC4_128_SHA                0x0300008E
# define TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA           0x0300008F
# define TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA            0x03000090
# define TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA            0x03000091
# define TLS1_CK_RSA_PSK_WITH_RC4_128_SHA                0x03000092
# define TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA           0x03000093
# define TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA            0x03000094
# define TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA            0x03000095

/* PSK ciphersuites from 5487 */
# define TLS1_CK_PSK_WITH_AES_128_GCM_SHA256             0x030000A8
# define TLS1_CK_PSK_WITH_AES_256_GCM_SHA384             0x030000A9
# define TLS1_CK_DHE_PSK_WITH_AES_128_GCM_SHA256         0x030000AA
# define TLS1_CK_DHE_PSK_WITH_AES_256_GCM_SHA384         0x030000AB
# define TLS1_CK_RSA_PSK_WITH_AES_128_GCM_SHA256         0x030000AC
# define TLS1_CK_RSA_PSK_WITH_AES_256_GCM_SHA384         0x030000AD
# define TLS1_CK_PSK_WITH_AES_128_CBC_SHA256             0x030000AE
# define TLS1_CK_PSK_WITH_AES_256_CBC_SHA384             0x030000AF
# define TLS1_CK_PSK_WITH_NULL_SHA256                    0x030000B0
# define TLS1_CK_PSK_WITH_NULL_SHA384                    0x030000B1
# define TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA256         0x030000B2
# define TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA384         0x030000B3
# define TLS1_CK_DHE_PSK_WITH_NULL_SHA256                0x030000B4
# define TLS1_CK_DHE_PSK_WITH_NULL_SHA384                0x030000B5
# define TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA256         0x030000B6
# define TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA384         0x030000B7
# define TLS1_CK_RSA_PSK_WITH_NULL_SHA256                0x030000B8
# define TLS1_CK_RSA_PSK_WITH_NULL_SHA384                0x030000B9

/* NULL PSK ciphersuites from RFC4785 */
# define TLS1_CK_PSK_WITH_NULL_SHA                       0x0300002C
# define TLS1_CK_DHE_PSK_WITH_NULL_SHA                   0x0300002D
# define TLS1_CK_RSA_PSK_WITH_NULL_SHA                   0x0300002E

/* AES ciphersuites from RFC3268 */
# define TLS1_CK_RSA_WITH_AES_128_SHA                    0x0300002F
# define TLS1_CK_DH_DSS_WITH_AES_128_SHA                 0x03000030
# define TLS1_CK_DH_RSA_WITH_AES_128_SHA                 0x03000031
# define TLS1_CK_DHE_DSS_WITH_AES_128_SHA                0x03000032
# define TLS1_CK_DHE_RSA_WITH_AES_128_SHA                0x03000033
# define TLS1_CK_ADH_WITH_AES_128_SHA                    0x03000034
# define TLS1_CK_RSA_WITH_AES_256_SHA                    0x03000035
# define TLS1_CK_DH_DSS_WITH_AES_256_SHA                 0x03000036
# define TLS1_CK_DH_RSA_WITH_AES_256_SHA                 0x03000037
# define TLS1_CK_DHE_DSS_WITH_AES_256_SHA                0x03000038
# define TLS1_CK_DHE_RSA_WITH_AES_256_SHA                0x03000039
# define TLS1_CK_ADH_WITH_AES_256_SHA                    0x0300003A

/* TLS v1.2 ciphersuites */
# define TLS1_CK_RSA_WITH_NULL_SHA256                    0x0300003B
# define TLS1_CK_RSA_WITH_AES_128_SHA256                 0x0300003C
# define TLS1_CK_RSA_WITH_AES_256_SHA256                 0x0300003D
# define TLS1_CK_DH_DSS_WITH_AES_128_SHA256              0x0300003E
# define TLS1_CK_DH_RSA_WITH_AES_128_SHA256              0x0300003F
# define TLS1_CK_DHE_DSS_WITH_AES_128_SHA256             0x03000040

/* Camellia ciphersuites from RFC4132 */
# define TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA           0x03000041
# define TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA        0x03000042
# define TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA        0x03000043
# define TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA       0x03000044
# define TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA       0x03000045
# define TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA           0x03000046

/* TLS v1.2 ciphersuites */
# define TLS1_CK_DHE_RSA_WITH_AES_128_SHA256             0x03000067
# define TLS1_CK_DH_DSS_WITH_AES_256_SHA256              0x03000068
# define TLS1_CK_DH_RSA_WITH_AES_256_SHA256              0x03000069
# define TLS1_CK_DHE_DSS_WITH_AES_256_SHA256             0x0300006A
# define TLS1_CK_DHE_RSA_WITH_AES_256_SHA256             0x0300006B
# define TLS1_CK_ADH_WITH_AES_128_SHA256                 0x0300006C
# define TLS1_CK_ADH_WITH_AES_256_SHA256                 0x0300006D

/* Camellia ciphersuites from RFC4132 */
# define TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA           0x03000084
# define TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA        0x03000085
# define TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA        0x03000086
# define TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA       0x03000087
# define TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA       0x03000088
# define TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA           0x03000089

/* SEED ciphersuites from RFC4162 */
# define TLS1_CK_RSA_WITH_SEED_SHA                       0x03000096
# define TLS1_CK_DH_DSS_WITH_SEED_SHA                    0x03000097
# define TLS1_CK_DH_RSA_WITH_SEED_SHA                    0x03000098
# define TLS1_CK_DHE_DSS_WITH_SEED_SHA                   0x03000099
# define TLS1_CK_DHE_RSA_WITH_SEED_SHA                   0x0300009A
# define TLS1_CK_ADH_WITH_SEED_SHA                       0x0300009B

/* TLS v1.2 GCM ciphersuites from RFC5288 */
# define TLS1_CK_RSA_WITH_AES_128_GCM_SHA256             0x0300009C
# define TLS1_CK_RSA_WITH_AES_256_GCM_SHA384             0x0300009D
# define TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256         0x0300009E
# define TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384         0x0300009F
# define TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256          0x030000A0
# define TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384          0x030000A1
# define TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256         0x030000A2
# define TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384         0x030000A3
# define TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256          0x030000A4
# define TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384          0x030000A5
# define TLS1_CK_ADH_WITH_AES_128_GCM_SHA256             0x030000A6
# define TLS1_CK_ADH_WITH_AES_256_GCM_SHA384           