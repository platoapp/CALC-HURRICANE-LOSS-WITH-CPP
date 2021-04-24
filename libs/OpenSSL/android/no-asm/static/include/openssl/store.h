/*
 * Copyright 2016-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_OSSL_STORE_H
# define HEADER_OSSL_STORE_H

# include <stdarg.h>
# include <openssl/ossl_typ.h>
# include <openssl/pem.h>
# include <openssl/storeerr.h>

# ifdef  __cplusplus
extern "C" {
# endif

/*-
 *  The main OSSL_STORE functions.
 *  ------------------------------
 *
 *  These allow applications to open a channel to a resource with supported
 *  data (keys, certs, crls, ...), read the data a piece at a time and decide
 *  what to do with it, and finally close.
 */

typedef struct ossl_store_ctx_st OSSL_STORE_CTX;

/*
 * Typedef for the OSSL_STORE_INFO post processing callback.  This can be used
 * to massage the given OSSL_STORE_INFO, or to drop it entirely (by returning
 * NULL).
 */
typedef OSSL_STORE_INFO *(*OSSL_STORE_post_process_info_fn)(OSSL_STORE_INFO *,
                                                            void *);

/*
 * Open a channel given a URI.  The given UI method will be used any time the
 * loader needs extra input, for example when a password or pin is needed, and
 * will be passed the same user data every time it's needed in this context.
 *
 * Returns a context reference which represents the channel to communicate
 * through.
 */
OSSL_STORE_CTX *OSSL_STORE_open(const char *uri, const UI_METHOD *ui_method,
                                void *ui_data,
                                OSSL_STORE_post_process_info_fn post_process,
                                void *post_process_data);

/*
 * Control / fine tune the OSSL_STORE channel.  |cmd| determines what is to be
 * done, and depends on the underlying loader (use OSSL_STORE_get0_scheme to
 * determine which loader is used), except for common commands (see below).
 * Each command takes different arguments.
 */
int OSSL_STORE_ctrl(OSSL_STORE_CTX *ctx, int cmd, ... /* args */);
int OSSL_STORE_vctrl(OSSL_STORE_CTX *ctx, int cmd, va_list args);

/*
 * Common ctrl commands that different loaders may choose to support.
 */
/* int on = 0 or 1; STORE_ctrl(ctx, STORE_C_USE_SECMEM, &on); */
# define OSSL_STORE_C_USE_SECMEM      1
/* Where custom commands start */
# define OSSL_STORE_C_CUSTOM_START    100

/*
 * Read one data item (a key, a cert, a CRL) that is supported by the OSSL_STORE
 * functionality, given a context.
 * Returns a OSSL_STORE_INFO pointer, from which OpenSSL typed data can be
 * extracted with OSSL_STORE_INFO_get0_PKEY(), OSSL_STORE_INFO_get0_CERT(), ...
 * NULL is returned on error, which may include that the data found at the URI
 * can't be figured out for certain or is ambiguous.
 */
OSSL_STORE_INFO *OSSL_STORE_load(OSSL_STORE_CTX *ctx);

/*
 * Check if end of data (end of file) is reached
 * Returns 1 on end, 0 otherwise.
 */
int OSSL_STORE_eof(OSSL_STORE_CTX *ctx);

/*
 * Check if an error occurred
 * Returns 1 if it did, 0 otherwise.
 */
int OSSL_STORE_error(OSSL_STORE_CTX *ctx);

/*
 * Close the channel
 * Returns 1 on success, 0 on error.
 */
int OSSL_STORE_close(OSSL_STORE_CTX *ctx);


/*-
 *  Extracting OpenSSL types from and creating new OSSL_STORE_INFOs
 *  ---------------------------------------------------------------
 */

/*
 * Types of data that can be ossl_stored in a OSSL_STORE_INFO.
 * OSSL_STORE_INFO_NAME is typically found when getting a listing of
 * available "files" / "tokens" / what have you.
 */
# define OSSL_STORE_INFO_NAME           1   /* char * */
# define OSSL_STORE_INFO_PARAMS         2   /* EVP_PKEY * */
# define OSSL_STORE_INFO_PKEY           3   /* EVP_PKEY * */
# define OSSL_STORE_INFO_CERT           4   /* X509 * */
# define OSSL_STORE_INFO_CRL            5   /* X509_CRL * */

/*
 * Functions to generate OSSL_STORE_INFOs, one function for each type we
 * support having in them, as well as a generic constructor.
 *
 * In all cases, ownership of the object is transferred to the OSSL_STORE_INFO
 * and will therefore be freed when the OSSL_STORE_INFO is freed.
 */
OSSL_STORE_INFO *OSSL_STORE_INFO_new_NAME(char *name);
int OSSL_STORE_INFO_set0_NAME_description(OSSL_STORE_INFO *info, char *desc);
OSSL_STORE_INFO *OSSL_STORE_INFO_new_PARAMS(EVP_PKEY *params);
OSSL_STORE_INFO *OSSL_STORE_INFO_new_PKEY(EVP_PKEY *pkey);
OSSL_STORE_INFO *OSSL_STORE_INFO_new_CERT(X509 *x509);
OSSL_STORE_INFO *OSSL_STORE_INFO_new_CRL(X509_CRL *crl);

/*
 * Functions to try to extract data from a OSSL_STORE_INFO.
 */
int OSSL_STORE_INFO_get_type(const OSSL_STORE_INFO *info);
const char *OSSL_STORE_INFO_get0_NAME(const OSSL_STORE_INFO *info);
char *OSSL_STORE_INFO_get1_NAME(const OSSL_STORE_INFO *info);
const char *OSSL_STORE_INFO_get0_NAME_description(const OSSL_STORE_INFO *info);
char *OSSL_STORE_INFO_get1_NAME_description(const OSSL_STORE_INFO *info);
EVP_PKEY *OSSL_STORE_INFO_get0_PARAMS(const OSSL_STORE_INFO *info);
EVP_PKEY *OSSL_STORE_INFO_get1_PARAMS(const OSSL_STORE_INFO *info);
EVP_PKEY *OSSL_STORE_INFO_get0_PKEY(const OSSL_STORE_INFO *info);
EVP_PKEY *OSSL_STORE_INFO_get1_PKEY(const OSSL_STORE_INFO *info);
X509 *OSSL_STORE_INFO_get0_CERT(const OSSL_STORE_INFO *info);
X509 *OSSL_STORE_INFO_get1_CERT(const OSSL_STORE_INFO *info);
X509_CRL *OSSL_STORE_INFO_get0_CRL(const OSSL_STORE_INFO *info);
X509_CRL *OSSL_STORE_INFO_get1_CRL(const OSSL_STORE_INFO *info);

const char *OSSL_STORE_INFO_type_string(int type);

/*
 * Free the OSSL_STORE_INFO
 */
void OSSL_STORE_INFO_free(OSSL_STORE_INFO *info);


/*-
 *  Functions to construct a search URI from a base URI and search criteria
 *  -----------------------------------------------------------------------
 */

/* OSSL_STORE search types */
# define OSSL_STORE_SEARCH_BY_NAME              1 /* subject in certs, issuer in CRLs */
# define OSSL_STORE_SEARCH_BY_ISSUER_SERIAL     2
# define OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT   3
# define OSSL_STORE_SEARCH_BY_ALIAS             4

/* To check what search types the scheme handler supports */
int OSSL_STORE_supports_search(OSSL_STORE_CTX *ctx, int search_type);

/* Search term constructors */
/*
 * The input is considered to be owned by the caller, and must therefore
 * remain present throughout the lifetime of the returned OSSL_STORE_SEARCH
 */
OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_name(X509_NAME *name);
OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_issuer_serial(X509_NAME *name,
                                                      const ASN1_INTEGER
                                                      *serial);
OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_key_fingerprint(const EVP_MD *digest,
                                                        const unsigned char
                                                        *bytes, size_t len);
OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_alias(const char *alias);

/* Search term destructor */
void OSSL_STORE_SEARCH_free(OSSL_STORE_SEARCH *search);

/* Search term accessors */
int OSSL_STORE_SEARCH_get_type(const OSSL_STORE_SEARCH *criterion);
X509_NAME *OSSL_STORE_SEARCH_get0_name(OSSL_STORE_SEARCH *criterion);
const ASN1_INTEGER *OSSL_STORE_SEARCH_get0_serial(const OSSL_STORE_SEARCH
                                                  *cr