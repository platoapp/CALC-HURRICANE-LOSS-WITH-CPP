/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_UI_H
# define HEADER_UI_H

# include <openssl/opensslconf.h>

# if OPENSSL_API_COMPAT < 0x10100000L
#  include <openssl/crypto.h>
# endif
# include <openssl/safestack.h>
# include <openssl/pem.h>
# include <openssl/ossl_typ.h>
# include <openssl/uierr.h>

/* For compatibility reasons, the macro OPENSSL_NO_UI is currently retained */
# if OPENSSL_API_COMPAT < 0x10200000L
#  ifdef OPENSSL_NO_UI_CONSOLE
#   define OPENSSL_NO_UI
#  endif
# endif

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * All the following functions return -1 or NULL on error and in some cases
 * (UI_process()) -2 if interrupted or in some other way cancelled. When
 * everything is fine, they return 0, a positive value or a non-NULL pointer,
 * all depending on their purpose.
 */

/* Creators and destructor.   */
UI *UI_new(void);
UI *UI_new_method(const UI_METHOD *method);
void UI_free(UI *ui);

/*-
   The following functions are used to add strings to be printed and prompt
   strings to prompt for data.  The names are UI_{add,dup}_<function>_string
   and UI_{add,dup}_input_boolean.

   UI_{add,dup}_<function>_string have the following meanings:
        add     add a text or prompt string.  The pointers given to these
                functions are used verbatim, no copying is done.
        dup     make a copy of the text or prompt string, then add the copy
                to the collection of strings in the user interface.
        <function>
                The function is a name for the functionality that the given
                string shall be used for.  It can be one of:
                        input   use the string as data prompt.
                        verify  use the string as verification prompt.  This
                                is used to verify a previous input.
                        info    use the string for informational output.
                        error   use the string for error output.
   Honestly, there's currently no difference between info and error for the
   moment.

   UI_{add,dup}_input_boolean have the same semantics for "add" and "dup",
   and are typically used when one wants to prompt for a yes/no response.

   All of the functions in this group take a UI and a prompt string.
   The string input and verify addition functions also take a flag argument,
   a buffer for the result to end up with, a minimum input size and a maximum
   input size (the result buffer MUST be large enough to be able to contain
   the maximum number of characters).  Additionally, the verify addition
   functions takes another buffer to compare the result against.
   The boolean input functions take an action description string (which should
   be safe to ignore if the expected user action is obvious, for example with
   a dialog box with an OK button and a Cancel button), a string of acceptable
   charac