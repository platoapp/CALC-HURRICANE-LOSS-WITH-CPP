
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
# define         EVP_CIPH_CUSTOM_IV              0x10
/* Set if the cipher's init() function should be called if key is NULL */
# define         EVP_CIPH_ALWAYS_CALL_INIT       0x20
/* Call ctrl() to init cipher parameters */
# define         EVP_CIPH_CTRL_INIT              0x40
/* Don't use standard key length function */
# define         EVP_CIPH_CUSTOM_KEY_LENGTH      0x80
/* Don't use standard block padding */
# define         EVP_CIPH_NO_PADDING             0x100
/* cipher handles random key generation */
# define         EVP_CIPH_RAND_KEY               0x200
/* cipher has its own additional copying logic */
# define         EVP_CIPH_CUSTOM_COPY            0x400
/* Don't use standard iv length function */
# define         EVP_CIPH_CUSTOM_IV_LENGTH       0x800
/* Allow use default ASN1 get/set iv */
# define         EVP_CIPH_FLAG_DEFAULT_ASN1      0x1000
/* Buffer length in bits not bytes: CFB1 mode only */
# define         EVP_CIPH_FLAG_LENGTH_BITS       0x2000
/* Note if suitable for use in FIPS mode */
# define         EVP_CIPH_FLAG_FIPS              0x4000
/* Allow non FIPS cipher in FIPS mode */
# define         EVP_CIPH_FLAG_NON_FIPS_ALLOW    0x8000
/*
 * Cipher handles any and all padding logic as well as finalisation.
 */
# define         EVP_CIPH_FLAG_CUSTOM_CIPHER     0x100000
# define         EVP_CIPH_FLAG_AEAD_CIPHER       0x200000
# define         EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0x400000
/* Cipher can handle pipeline operations */
# define         EVP_CIPH_FLAG_PIPELINE          0X800000

/*
 * Cipher context flag to indicate we can handle wrap mode: if allowed in
 * older applications it could overflow buffers.
 */

# define         EVP_CIPHER_CTX_FLAG_WRAP_ALLOW  0x1

/* ctrl() values */

# define         EVP_CTRL_INIT                   0x0
# define         EVP_CTRL_SET_KEY_LENGTH         0x1
# define         EVP_CTRL_GET_RC2_KEY_BITS       0x2
# define         EVP_CTRL_SET_RC2_KEY_BITS       0x3
# define         EVP_CTRL_GET_RC5_ROUNDS         0x4
# define         EVP_CTRL_SET_RC5_ROUNDS         0x5
# define         EVP_CTRL_RAND_KEY               0x6
# define         EVP_CTRL_PBE_PRF_NID            0x7
# define         EVP_CTRL_COPY                   0x8
# define         EVP_CTRL_AEAD_SET_IVLEN         0x9
# define         EVP_CTRL_AEAD_GET_TAG           0x10
# define         EVP_CTRL_AEAD_SET_TAG           0x11
# define         EVP_CTRL_AEAD_SET_IV_FIXED      0x12
# define         EVP_CTRL_GCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
# define         EVP_CTRL_GCM_GET_TAG            EVP_CTRL_AEAD_GET_TAG
# define         EVP_CTRL_GCM_SET_TAG            EVP_CTRL_AEAD_SET_TAG
# define         EVP_CTRL_GCM_SET_IV_FIXED       EVP_CTRL_AEAD_SET_IV_FIXED
# define         EVP_CTRL_GCM_IV_GEN             0x13
# define         EVP_CTRL_CCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
# define         EVP_CTRL_CCM_GET_TAG            EVP_CTRL_AEAD_GET_TAG
# define         EVP_CTRL_CCM_SET_TAG            EVP_CTRL_AEAD_SET_TAG
# define         EVP_CTRL_CCM_SET_IV_FIXED       EVP_CTRL_AEAD_SET_IV_FIXED
# define         EVP_CTRL_CCM_SET_L              0x14
# define         EVP_CTRL_CCM_SET_MSGLEN         0x15
/*
 * AEAD cipher deduces payload length and returns number of bytes required to
 * store MAC and eventual padding. Subsequent call to EVP_Cipher even
 * appends/verifies MAC.
 */
# define         EVP_CTRL_AEAD_TLS1_AAD          0x16
/* Used by composite AEAD ciphers, no-op in GCM, CCM... */
# define         EVP_CTRL_AEAD_SET_MAC_KEY       0x17
/* Set the GCM invocation field, decrypt only */
# define         EVP_CTRL_GCM_SET_IV_INV         0x18

# define         EVP_CTRL_TLS1_1_MULTIBLOCK_AAD  0x19
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT      0x1a
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT      0x1b
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE  0x1c

# define         EVP_CTRL_SSL3_MASTER_SECRET             0x1d

/* EVP_CTRL_SET_SBOX takes the char * specifying S-boxes */
# define         EVP_CTRL_SET_SBOX                       0x1e
/*
 * EVP_CTRL_SBOX_USED takes a 'size_t' and 'char *', pointing at a
 * pre-allocated buffer with specified size
 */
# define         EVP_CTRL_SBOX_USED                      0x1f
/* EVP_CTRL_KEY_MESH takes 'size_t' number of bytes to mesh the key after,
 * 0 switches meshing off
 */
# define         EVP_CTRL_KEY_MESH                       0x20
/* EVP_CTRL_BLOCK_PADDING_MODE takes the padding mode */
# define         EVP_CTRL_BLOCK_PADDING_MODE             0x21

/* Set the output buffers to use for a pipelined operation */
# define         EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS       0x22
/* Set the input buffers to use for a pipelined operation */
# define         EVP_CTRL_SET_PIPELINE_INPUT_BUFS        0x23
/* Set the input buffer lengths to use for a pipelined operation */
# define         EVP_CTRL_SET_PIPELINE_INPUT_LENS        0x24

# define         EVP_CTRL_GET_IVLEN                      0x25

/* Padding modes */
#define EVP_PADDING_PKCS7       1
#define EVP_PADDING_ISO7816_4   2
#define EVP_PADDING_ANSI923     3
#define EVP_PADDING_ISO10126    4
#define EVP_PADDING_ZERO        5

/* RFC 5246 defines additional data to be 13 bytes in length */
# define         EVP_AEAD_TLS1_AAD_LEN           13

typedef struct {
    unsigned char *out;
    const unsigned char *inp;
    size_t len;
    unsigned int interleave;
} EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;

/* GCM TLS constants */
/* Length of fixed part of IV derived from PRF */
# define EVP_GCM_TLS_FIXED_IV_LEN                        4
/* Length of explicit part of IV part of TLS records */
# define EVP_GCM_TLS_EXPLICIT_IV_LEN                     8
/* Length of tag for TLS */
# define EVP_GCM_TLS_TAG_LEN                             16

/* CCM TLS constants */
/* Length of fixed part of IV derived from PRF */
# define EVP_CCM_TLS_FIXED_IV_LEN                        4
/* Length of explicit part of IV part of TLS records */
# define EVP_CCM_TLS_EXPLICIT_IV_LEN                     8
/* Total length of CCM IV length for TLS */
# define EVP_CCM_TLS_IV_LEN                              12
/* Length of tag for TLS */
# define EVP_CCM_TLS_TAG_LEN                             16
/* Length of CCM8 tag for TLS */
# define EVP_CCM8_TLS_TAG_LEN                            8

/* Length of tag for TLS */
# define EVP_CHACHAPOLY_TLS_TAG_LEN                      16

typedef struct evp_cipher_info_st {
    const EVP_CIPHER *cipher;
    unsigned char iv[EVP_MAX_IV_LENGTH];
} EVP_CIPHER_INFO;


/* Password based encryption function */
typedef int (EVP_PBE_KEYGEN) (EVP_CIPHER_CTX *ctx, const char *pass,
                              int passlen, ASN1_TYPE *param,
                              const EVP_CIPHER *cipher, const EVP_MD *md,
                              int en_de);

# ifndef OPENSSL_NO_RSA
#  define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
                                        (char *)(rsa))
# endif

# ifndef OPENSSL_NO_DSA
#  define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA,\
                                        (char *)(dsa))
# endif

# ifndef OPENSSL_NO_DH
#  define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH,\
                                        (char *)(dh))
# endif

# ifndef OPENSSL_NO_EC
#  define EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey),EVP_PKEY_EC,\
                                        (char *)(eckey))
# endif
# ifndef OPENSSL_NO_SIPHASH
#  define EVP_PKEY_assign_SIPHASH(pkey,shkey) EVP_PKEY_assign((pkey),EVP_PKEY_SIPHASH,\
                                        (char *)(shkey))
# endif

# ifndef OPENSSL_NO_POLY1305
#  define EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey),EVP_PKEY_POLY1305,\
                                        (char *)(polykey))
# endif

/* Add some extra combinations */
# define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a))
# define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a))
# define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a))
# define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a))

int EVP_MD_type(const EVP_MD *md);
# define EVP_MD_nid(e)                   EVP_MD_type(e)
# define EVP_MD_name(e)                  OBJ_nid2sn(EVP_MD_nid(e))
int EVP_MD_pkey_type(const EVP_MD *md);
int EVP_MD_size(const EVP_MD *md);
int EVP_MD_block_size(const EVP_MD *md);
unsigned long EVP_MD_flags(const EVP_MD *md);

const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx);
int (*EVP_MD_CTX_update_fn(EVP_MD_CTX *ctx))(EVP_MD_CTX *ctx,
                                             const void *data, size_t count);
void EVP_MD_CTX_set_update_fn(EVP_MD_CTX *ctx,
                              int (*update) (EVP_MD_CTX *ctx,
                                             const void *data, size_t count));
# define EVP_MD_CTX_size(e)              EVP_MD_size(EVP_MD_CTX_md(e))
# define EVP_MD_CTX_block_size(e)        EVP_MD_block_size(EVP_MD_CTX_md(e))
# define EVP_MD_CTX_type(e)              EVP_MD_type(EVP_MD_CTX_md(e))
EVP_PKEY_CTX *EVP_MD_CTX_pkey_ctx(const EVP_MD_CTX *ctx);
void EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx);
void *EVP_MD_CTX_md_data(const EVP_MD_CTX *ctx);

int EVP_CIPHER_nid(const EVP_CIPHER *cipher);
# define EVP_CIPHER_name(e)              OBJ_nid2sn(EVP_CIPHER_nid(e))
int EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_key_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);
unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher);
# define EVP_CIPHER_mode(e)              (EVP_CIPHER_flags(e) & EVP_CIPH_MODE)

const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);
const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
const unsigned char *EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_num(const EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num);
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);
void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);
void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);
void *EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX *ctx, void *cipher_data);
# define EVP_CIPHER_CTX_type(c)         EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c))
# if OPENSSL_API_COMPAT < 0x10100000L
#  define EVP_CIPHER_CTX_flags(c)       EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(c))
# endif
# define EVP_CIPHER_CTX_mode(c)         EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(c))

# define EVP_ENCODE_LENGTH(l)    ((((l)+2)/3*4)+((l)/48+1)*2+80)
# define EVP_DECODE_LENGTH(l)    (((l)+3)/4*3+80)

# define EVP_SignInit_ex(a,b,c)          EVP_DigestInit_ex(a,b,c)
# define EVP_SignInit(a,b)               EVP_DigestInit(a,b)
# define EVP_SignUpdate(a,b,c)           EVP_DigestUpdate(a,b,c)
# define EVP_VerifyInit_ex(a,b,c)        EVP_DigestInit_ex(a,b,c)
# define EVP_VerifyInit(a,b)             EVP_DigestInit(a,b)
# define EVP_VerifyUpdate(a,b,c)         EVP_DigestUpdate(a,b,c)
# define EVP_OpenUpdate(a,b,c,d,e)       EVP_DecryptUpdate(a,b,c,d,e)
# define EVP_SealUpdate(a,b,c,d,e)       EVP_EncryptUpdate(a,b,c,d,e)
# define EVP_DigestSignUpdate(a,b,c)     EVP_DigestUpdate(a,b,c)
# define EVP_DigestVerifyUpdate(a,b,c)   EVP_DigestUpdate(a,b,c)

# ifdef CONST_STRICT
void BIO_set_md(BIO *, const EVP_MD *md);
# else
#  define BIO_set_md(b,md)          BIO_ctrl(b,BIO_C_SET_MD,0,(char *)(md))
# endif
# define BIO_get_md(b,mdp)          BIO_ctrl(b,BIO_C_GET_MD,0,(char *)(mdp))
# define BIO_get_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_GET_MD_CTX,0, \
                                             (char *)(mdcp))
# define BIO_set_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_SET_MD_CTX,0, \
                                             (char *)(mdcp))
# define BIO_get_cipher_status(b)   BIO_ctrl(b,BIO_C_GET_CIPHER_STATUS,0,NULL)
# define BIO_get_cipher_ctx(b,c_pp) BIO_ctrl(b,BIO_C_GET_CIPHER_CTX,0, \
                                             (char *)(c_pp))

/*__owur*/ int EVP_Cipher(EVP_CIPHER_CTX *c,
                          unsigned char *out,
                          const unsigned char *in, unsigned int inl);

# define EVP_add_cipher_alias(n,alias) \
        OBJ_NAME_add((alias),OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS,(n))
# define EVP_add_digest_alias(n,alias) \
        OBJ_NAME_add((alias),OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS,(n))
# define EVP_delete_cipher_alias(alias) \
        OBJ_NAME_remove(alias,OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);
# define EVP_delete_digest_alias(alias) \
        OBJ_NAME_remove(alias,OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);

int EVP_MD_CTX_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
EVP_MD_CTX *EVP_MD_CTX_new(void);
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
# define EVP_MD_CTX_create()     EVP_MD_CTX_new()
# define EVP_MD_CTX_init(ctx)    EVP_MD_CTX_reset((ctx))
# define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))
__owur int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);
void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags);
int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags);
__owur int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
                                 ENGINE *impl);
__owur int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d,
                                size_t cnt);
__owur int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
                                  unsigned int *s);
__owur int EVP_Digest(const void *data, size_t count,
                          unsigned char *md, unsigned int *size,
                          const EVP_MD *type, ENGINE *impl);

__owur int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in);
__owur int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
__owur int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md,
                           unsigned int *s);
__owur int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *md,
                              size_t len);

int EVP_read_pw_string(char *buf, int length, const char *prompt, int verify);
int EVP_read_pw_string_min(char *buf, int minlen, int maxlen,
                           const char *prompt, int verify);
void EVP_set_pw_prompt(const char *prompt);
char *EVP_get_pw_prompt(void);

__owur int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
                          const unsigned char *salt,
                          const unsigned char *data, int datal, int count,
                          unsigned char *key, unsigned char *iv);

void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);
void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags);
int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags);

__owur int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
/*__owur*/ int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
                                  const EVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
/*__owur*/ int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
/*__owur*/ int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   int *outl);
/*__owur*/ int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl);

__owur int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
/*__owur*/ int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
                                  const EVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
/*__owur*/ int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
__owur int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                            int *outl);
/*__owur*/ int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                   int *outl);

__owur int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                          const unsigned char *key, const unsigned char *iv,
                          int enc);
/*__owur*/ int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
                                 const EVP_CIPHER *cipher, ENGINE *impl,
                                 const unsigned char *key,
                                 const unsigned char *iv, int enc);
__owur int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            int *outl, const unsigned char *in, int inl);
__owur int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                           int *outl);
__owur int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                              int *outl);

__owur int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
                         EVP_PKEY *pkey);

__owur int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
                          size_t *siglen, const unsigned char *tbs,
                          size_t tbslen);

__owur int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                           unsigned int siglen, EVP_PKEY *pkey);

__owur int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
                            size_t siglen, const unsigned char *tbs,
                            size_t tbslen);

/*__owur*/ int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                  const EVP_MD *type, ENGINE *e,
                                  EVP_PKEY *pkey);
__owur int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                               size_t *siglen);

__owur int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                const EVP_MD *type, ENGINE *e,
                                EVP_PKEY *pkey);
__owur int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig,
                                 size_t siglen);

# ifndef OPENSSL_NO_RSA
__owur int EVP_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        const unsigned char *ek, int ekl,
                        const unsigned char *iv, EVP_PKEY *priv);
__owur int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

__owur int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        unsigned char **ek, int *ekl, unsigned char *iv,
                        EVP_PKEY **pubk, int npubk);
__owur int EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
# endif

EVP_ENCODE_CTX *EVP_ENCODE_CTX_new(void);
void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx);
int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX *dctx, EVP_ENCODE_CTX *sctx);
int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX *ctx);
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
int EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl);
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);
int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);

void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl);
int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned
                    char *out, int *outl);
int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);

# if OPENSSL_API_COMPAT < 0x10100000L
#  define EVP_CIPHER_CTX_init(c)      EVP_CIPHER_CTX_reset(c)
#  define EVP_CIPHER_CTX_cleanup(c)   EVP_CIPHER_CTX_reset(c)
# endif
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);

const BIO_METHOD *BIO_f_md(void);
const BIO_METHOD *BIO_f_base64(void);
const BIO_METHOD *BIO_f_cipher(void);
const BIO_METHOD *BIO_f_reliable(void);
__owur int BIO_set_cipher(BIO *b, const EVP_CIPHER *c, const unsigned char *k,
                          const unsigned char *i, int enc);

const EVP_MD *EVP_md_null(void);
# ifndef OPENSSL_NO_MD2
const EVP_MD *EVP_md2(void);
# endif
# ifndef OPENSSL_NO_MD4
const EVP_MD *EVP_md4(void);
# endif
# ifndef OPENSSL_NO_MD5
const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_md5_sha1(void);
# endif
# ifndef OPENSSL_NO_BLAKE2
const EVP_MD *EVP_blake2b512(void);
const EVP_MD *EVP_blake2s256(void);
# endif
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
const EVP_MD *EVP_sha512_224(void);
const EVP_MD *EVP_sha512_256(void);
const EVP_MD *EVP_sha3_224(void);
const EVP_MD *EVP_sha3_256(void);
const EVP_MD *EVP_sha3_384(void);
const EVP_MD *EVP_sha3_512(void);
const EVP_MD *EVP_shake128(void);
const EVP_MD *EVP_shake256(void);
# ifndef OPENSSL_NO_MDC2
const EVP_MD *EVP_mdc2(void);
# endif
# ifndef OPENSSL_NO_RMD160
const EVP_MD *EVP_ripemd160(void);
# endif
# ifndef OPENSSL_NO_WHIRLPOOL
const EVP_MD *EVP_whirlpool(void);
# endif
# ifndef OPENSSL_NO_SM3
const EVP_MD *EVP_sm3(void);
# endif
const EVP_CIPHER *EVP_enc_null(void); /* does nothing :-) */
# ifndef OPENSSL_NO_DES
const EVP_CIPHER *EVP_des_ecb(void);
const EVP_CIPHER *EVP_des_ede(void);
const EVP_CIPHER *EVP_des_ede3(void);
const EVP_CIPHER *EVP_des_ede_ecb(void);
const EVP_CIPHER *EVP_des_ede3_ecb(void);
const EVP_CIPHER *EVP_des_cfb64(void);
#  define EVP_des_cfb EVP_des_cfb64
const EVP_CIPHER *EVP_des_cfb1(void);
const EVP_CIPHER *EVP_des_cfb8(void);
const EVP_CIPHER *EVP_des_ede_cfb64(void);
#  define EVP_des_ede_cfb EVP_des_ede_cfb64
const EVP_CIPHER *EVP_des_ede3_cfb64(void);
#  define EVP_des_ede3_cfb EVP_des_ede3_cfb64
const EVP_CIPHER *EVP_des_ede3_cfb1(void);
const EVP_CIPHER *EVP_des_ede3_cfb8(void);
const EVP_CIPHER *EVP_des_ofb(void);
const EVP_CIPHER *EVP_des_ede_ofb(void);
const EVP_CIPHER *EVP_des_ede3_ofb(void);
const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_des_ede_cbc(void);
const EVP_CIPHER *EVP_des_ede3_cbc(void);
const EVP_CIPHER *EVP_desx_cbc(void);
const EVP_CIPHER *EVP_des_ede3_wrap(void);
/*
 * This should now be supported through the dev_crypto ENGINE. But also, why
 * are rc4 and md5 declarations made here inside a "NO_DES" precompiler
 * branch?
 */
# endif
# ifndef OPENSSL_NO_RC4
const EVP_CIPHER *EVP_rc4(void);
const EVP_CIPHER *EVP_rc4_40(void);
#  ifndef OPENSSL_NO_MD5
const EVP_CIPHER *EVP_rc4_hmac_md5(void);
#  endif
# endif
# ifndef OPENSSL_NO_IDEA
const EVP_CIPHER *EVP_idea_ecb(void);
const EVP_CIPHER *EVP_idea_cfb64(void);
#  define EVP_idea_cfb EVP_idea_cfb64