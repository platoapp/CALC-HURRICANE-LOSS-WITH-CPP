/**
 * Copyright 2021 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#include "include/QX509Store.h"

QSimpleCrypto::QX509Store::QX509Store()
{
}

///
/// \brief QSimpleCrypto::QX509::addCertificateToStore
/// \param store - OpenSSL X509_STORE.
/// \param x509 - OpenSSL X509.
/// \return Returns 'true' on success and 'false', if error happened.
///
bool QSimpleCrypto::QX509Store::addCertificateToStore(X509_STORE* store, X509* x509)
{
    if (!X509_STORE_add_cert(store, x509)) {
        QSimpleCrypto::QX509Store::error.setError(1, "Couldn't add certificate to X509_STORE. X509_STORE_add_cert(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::addLookup
/// \param store - OpenSSL X509_STORE.
/// \param method - OpenSSL X509_LOOKUP_METHOD. Example: X509_LOOKUP_file.
/// \return Returns 'true' on success and 'false', if error happened.
///
bool QSimpleCrypto::QX509Store::addLookup(X509_STORE* store, X509_LOOKUP_METHOD* method)
{
    if (!X509_STORE_add_lookup(store, method)) {
        QSimpleCrypto::QX509Store::error.setError(1, "Couldn't add lookup to X509_STORE. X509_STORE_add_lookup(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::setCertificateDepth
/// \param store - OpenSSL X509_STORE.
/// \param depth - That is the maximum number of untrusted CA certificates that can appear in a chain. Example: 0.
/// \return Returns 'true' on success and 'false', if error happened.
///
bool QSimpleCrypto::QX509Store::setDepth(X509_STORE* store, const int& depth)
{
    if (!X509_STORE_set_depth(store, depth)) {
        QSimpleCrypto::QX509Store::error.setError(1, "Couldn't set depth for X509_STORE. X509_STORE_set_depth(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::setFlag
/// \param store - OpenSSL X509_STORE.
/// \param flag - The verification flags consists of zero or more of the following flags ored together. Example: X509_V_FLAG_CRL_CHECK.
/// \return Returns 'true' on success and 'false', if error happened.
///
bool QSimpleCrypto::QX509Store::setFlag(X509_STORE* store, const unsigned long& flag)
{
    if (!X509_STORE_set_flags(store, flag)) {
        QSimpleCrypto::Q