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
# define TLSEXT_hash_sha1 