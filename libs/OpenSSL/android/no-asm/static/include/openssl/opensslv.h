/*
 * Copyright 1999-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_OPENSSLV_H
# define HEADER_OPENSSLV_H

#ifdef  __cplusplus
extern "C" {
#endif

/*-
 * Numeric release version identifier:
 * MNNFFPPS: major minor fix patch status
 * The status nibble has one of the values 0 for development, 1 to e for betas
 * 1 to 14, and f for release.  The patch level is exactly that.
 * For example:
 * 0.9.3-dev      0x00903000
 * 0.9.3-beta1    0x00903001
 * 0.9.3-beta2-dev 0x00903002
 * 0.9.3-beta2    0x00903002 (same as ...beta2-dev)
 * 0.9.3          0x0090300f
 * 0.9.3a         0x0090301f
 * 0.9.4          0x0090400f
 * 1.2.3z         0x102031af
 *
 * For continuity reasons (because 0.9.5 is already out, and is coded
 * 0x00905100), between 0.9.5 and 0.9.6 the coding of the patch level
 * part is slightly different, by setting the highest bit.  This means
 * that 0.9.5a looks like this: 0x0090581f.  At 0.9.6, we can start
 * with 0x0090600S...
 *
 * (Prior to 0.9.3-dev a different scheme was used: 0.9.2b is 0x0922.)
 * (Prior to 0.9.5a beta1, a different scheme was used: MMNNFFRBB for
 *  major minor fix final patch/beta)
 */
# define OPENSSL_VERSION_NUMBER  0x1010107fL
# define OPENSSL_VERSION_TEXT    "OpenSSL 1.1.1g  21 Apr 2020"

/*-
 * The macros below are to be used for shared library (.so, .dll, ...)
 * versioning.  That kind of versioning works a bit differently between
 * operating systems.  The most usual scheme is to set a major and a minor
 * number, and have the runtime loader check that the major number is equal
 * to what it was at application link time, while the minor number has to
 * be greater or equal to what it was at application link time.  With this
 * scheme, the version number is usually part of the file name, like this:
 *
 *      libcrypto.so.0.9
 *
 * Some unixen also make a softlink with the major version number only:
 *
 *      libcrypto.so.0
 *
 * On Tru64 and IRIX 6.x it works a little bit differently.  There, the
 * shared library version is stored in the file, and is actually a series
 * of versions, separated by colons.  The rightmost version present in the
 * library when linking an application is stored in the application to be
 * matched at run time.  When the application is run, a check is done to
 * see if the library version stored in the application matches any of the
 * versions in the version string of the library itself.
 * This version string can be constructed in any way, depending on wha