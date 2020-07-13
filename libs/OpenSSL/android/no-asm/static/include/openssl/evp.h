/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ENVELOPE_H
# define HEADER_ENVELOPE_H

# include <openssl/opensslconf.h>
# include <openssl/ossl_typ.h>
# include <openssl/symhacks.h>
# include <openssl/bio.h>
# include <openssl/evperr.h>

# define EVP_MAX_MD_SIZE                 64/* longest known is SHA512 */
# define EVP_MAX_KEY_LENGTH              64
# define EVP_MAX_IV_LENGTH               16
# define EVP_MAX_BLOCK_LENGTH            32

# define PKCS5_SALT_LEN                  8
/* Default PKCS#5 iteration count */
# define PKCS5_DEFAULT_ITER              2048

# include <openssl/objects.h>

# define EVP_PK_RSA      0x0001
# define EVP_PK_DSA      0x0002
# define EVP_PK_DH       0x0004
# define EVP_PK_EC       0x0008
# define EVP_PKT_SIGN    0x0010
# define EVP_PKT_ENC     0x0020
# define EVP_PKT_EXCH    0x0040
# define EVP_PKS_RSA     0x0100
# define EVP_PKS_DSA     0x0200
# define EVP_PKS_EC      0x0400

# define EVP_PKEY_NONE   NID_undef
# define EVP_PKEY_RSA    NID_rsaEncryption
# define EVP_PKEY_RSA2   NID_rsa
# define EVP_PKEY_RSA_PSS NID_rsassaPss
# define EVP_PKEY_DSA    NID_dsa
# define EVP_PKEY_DSA1   NID_dsa_2
# define EVP_PKEY_DSA2   NID_dsaWithSHA
# define EVP_PKEY_DSA3   NID_dsaWithSHA1
# define EVP_PKEY_DSA4   NID_dsaWithSHA1_2
# define EVP_PKEY_DH     NID_dhKeyAgreement
# define EVP_PKEY_DHX    NID_dhpublicnumber
# define EVP_PKEY_EC     NID_X9_62_id_ecPublicKey
# define EVP_PKEY_SM2    NID_sm2
# define EVP_PKEY_HMAC   NID_hmac
# define EVP_PKEY_CMAC   NID_cmac
# define EVP_PKEY_SCRYPT NID_id_scrypt
# define EVP_PKEY_TLS1_PRF NID_tls1_prf
# define EVP_PKEY_HKDF   NID_hkdf
# define EVP_PKEY_POLY1305 NID_poly1305
# define EVP_PKEY_SIPHASH NID_siphash
# define EVP_PKEY_X25519 NID_X25519
# define EVP_PKEY_ED25519 NID_ED25519
# define EVP_PKEY_X448 NID_X448
# define EVP_PKEY_ED448 NID_ED448

#ifdef  __cplusplus
extern "C" {
#endif

# define EVP_PKEY_MO_SIGN        0x0001
# define EVP_PKEY_MO_VERIFY      0x0002
# define EVP_PKEY_MO_ENCRYPT     0x0004
# define EVP_PKEY_MO_DECRYPT     0x0008

# ifndef EVP_MD
EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type);
EVP_MD *EVP_MD_meth_dup(const EVP_MD *md);
void EVP_MD_meth_free(EVP_MD *md);

int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize);
int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize);
int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize);
int EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags);
int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx));
int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count));
int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx,
                                                   unsigned char *md));
int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to,
                                                 const EVP_MD_CTX *from));
int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx));
int EVP_MD_meth_set_ctrl(EVP_MD *md, int (*ctrl)(EVP_MD_CTX *ctx, int cmd,
                                                 int p1, void *p2));

int EVP_MD_meth_get_input_blocksize(const EVP_MD *md);
int EVP_MD_meth_get_result_size(const EVP_MD *md);
int EVP_MD_meth_get_app_datasize(const EVP_MD *md);
unsigned long EVP_MD_meth_get_flags(const EVP_MD *md);
int (*EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx);
int (*EVP_MD_meth_get_update(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                                const void *data,
                                                size_t count);
int (*EVP_MD_meth_get_final(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                               unsigned char *md);
int (*EVP_MD_meth_get_copy(const EVP_MD *md))(EVP_MD_CTX *to,
                                              const EVP_MD_CTX *from);
int (*EVP_MD_meth_get_cleanup(const EVP_MD *md))(EVP_MD_CTX *ctx);
int (*EVP_MD_meth_get_ctrl(const EVP_MD *md))(EVP_MD_CTX *ctx, int cmd,
                                              int p1, void *p2);

/* digest can only handle a single block */
#  define EVP_MD_FLAG_ONESHOT     0x0001

/* digest is extensible-output function, XOF */
#  define EVP_MD_FLAG_XOF         0x0002

/* DigestAlgorithmIdentifier flags... */

#  define EVP_MD_FLAG_DIGALGID_MASK               0x0018

/* NULL or absent parameter accepted. Use NULL */

#  define EVP_MD_FLAG_DIGALGID_NULL               0x0000

/* NULL or absent parameter accepted. Use NULL for PKCS#1 otherwise absent */

#  define EVP_MD_FLAG_DIGALGID_ABSENT             0x0008

/* Custom handling via ctrl */

#  define EVP_MD_FLAG_DIGALGID_CUSTOM             0x0018

/* Note if suitable for use in FIPS mode */
#  define EVP_MD_FLAG_FIPS        0x0400

/* Digest ctrls */

#  define EVP_MD_CTRL_DIGALGID                    0x1
#  define EVP_MD_CTRL_MICALG                      0x2
#  define EVP_MD_CTRL_XOF_LEN                     0x3

/* Minimum Algorithm specific ctrl value */

#  define EVP_MD_CTRL_ALG_CTRL                    0x1000

# endif                         /* !EVP_MD */

/* values for EVP_MD_CTX flags */

# define EVP_MD_CTX_FLAG_ONESHOT         0x0001/* digest update will be
                                                * called once only */
# define EVP_MD_CTX_FLAG_CLEANED         0x0002/* context has already been
                                                * cleaned */
# define EVP_MD_CTX_FLAG_REUSE           0x0004/* Don't free up ctx->md_data
                                                * in EVP_MD_CTX_reset */
/*
 * FIPS and pad options are ignored in 1.0.0, definitions are here so we
 * don't accidentally reuse the values for other purposes.
 */

# define EVP_MD_CTX_FLAG_NON_FIPS_ALLOW  0x0008/* Allow use of non FIPS
                                                * digest in FIPS mode */

/*
 * The following PAD options are also currently ignored in 1.0.0, digest
 * parameters are handled through EVP_DigestSign*() and EVP_DigestVerify*()
 * instead.
 */
# define EVP_MD_CTX_FLAG_PAD_MASK        0xF0/* RSA mode to use */
# define EVP_MD_CTX_FLAG_PAD_PKCS1       0x00/* PKCS#1 v1.5 mode */
# define EVP_MD_CTX_FLAG_PAD_X931        0x10/* X9.31 mode */
# define EVP_MD_CTX_FLAG_PAD_PSS         0x20/* PSS mode */

# define EVP_MD_CTX_FLAG_NO_INIT         0x0100/* Don't initialize md_data */
/*
 * Some functions such as EVP_DigestSign only finalise copies of internal
 * contexts so additional data can be included after the finalisation call.
 * This is inefficient if this functionality is not required: it is disabled
 * if the following flag is set.
 */
# define EVP_MD_CTX_FLAG_FINALISE        0x0200
/* NOTE: 0x0400 is reserved for internal usage */

EVP_CIPHER *EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len);
EVP_CIPHER *EVP_CIPHER_meth_dup(const EVP_CIPHER *cipher);
void EVP_CIPHER_meth_free(EVP_CIPHER *cipher);

int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len);
int EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags);
int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER *cipher, int ctx_size);
int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
                             int (*init) (EVP_CIPHER_CTX *ctx,
                                          const unsigned char *key,
                                          const unsigned char *iv,
                                          int enc));
int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher,
                                  int (*do_cipher) (EVP_CIPHER_CTX *ctx,
                                                    unsigned char *out,
                                                    const unsigned char *in,
                                                    size_t inl));
int EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher,
                                int (*cleanup) (EVP_CIPHER_CTX *));
int EVP_CIPHER_meth_set_set_asn1_params(EVP_CIPHER *cipher,
                                        int (*set_asn1_parameters) (EVP_CIPHER_CTX *,
                                                                    ASN1_TYPE *));
int EVP_CIPHER_meth_set_get_asn1_params(EVP_CIPHER *cipher,
                                        int (*get_asn1_parameters) (EVP_CIPHER_CTX *,
                                                                    ASN1_TYPE *));
int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER *cipher,
                             int (*ctrl) (EVP_CIPHER_CTX *, int type,
                                          int arg, void *ptr));

int (*EVP_CIPHER_meth_get_init(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *ctx,
                                                          const unsigned char *key,
                                                          const unsigned char *iv,
                                                          int enc);
int (*EVP_CIPHER_meth_get_do_cipher(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *ctx,
                                                               unsigned char *out,
                                                               const unsigned char *in,
                                                               size_t inl);
int (*EVP_CIPHER_meth_get_cleanup(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *);
int (*EVP_CIPHER_meth_get_set_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
                                                                     ASN1_TYPE *);
int (*EVP_CIPHER_meth_get_get_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
                                                               ASN1_TYPE *);
int (*EVP_CIPHER_meth_get_ctrl(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
                                                          int type, int arg,
                                                          void *ptr);

/* Values for cipher flags */

/* Modes for ciphers */

# define         EVP_CIPH_STREAM_CIPHER          0x0
# define         EVP_CIPH_ECB_MODE               0x1
# define         EVP_CIPH_CBC_MODE               0x2
# define         EVP_CIPH_CFB_MODE               0x3
# define         EVP_CIPH_OFB_MODE               0x4
# define         EVP_CIPH_CTR_MODE               0x5
# define         EVP_CIPH_GCM_MODE               0x6
# define         EVP_CIPH_CCM_MODE               0x7
# define         EVP_CIPH_XTS_MODE               0x10001
# define         EVP_CIPH_WRAP_MODE              0x10002
# define         EVP_CIPH_OCB_MODE               0x10003
# define         EVP_CIPH_MODE                   0xF0007
/* Set if variable length cipher */
# define         EVP_CIPH_VARIABLE_LENGTH        0x8
/* Set if the iv handling should be done by the cipher itself */
# define         EVP_CIPH