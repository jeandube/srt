/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2019 Haivision Systems Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */


/*****************************************************************************
written by
   Haivision Systems Inc.

   2019-06-26 (jdube)
        OpenSSL Direct AES CRYSPR/4SRT (CRYypto Service PRovider for SRT).
*****************************************************************************/

#ifndef CRYSPR_OPENSSL_H
#define CRYSPR_OPENSSL_H

#include <openssl/evp.h>	/* PKCS5_xxx() */
#include <openssl/aes.h>	/* AES_xxx() */
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(OPENSSL_IS_BORINGSSL))
#include <openssl/modes.h>  /* CRYPTO_xxx() */
#endif
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/opensslv.h> /* OPENSSL_VERSION_NUMBER */

#ifdef CRYSPR_FIPSMODE
/* Define CRYSPR_HAS_FIPSMODE to 1 if this CRYSPR can operate in FIPS 140.2 mode.
*/
    #if ((OPENSSL_VERSION_NUMBER >= 0x1000100fL) && (OPENSSL_VERSION_NUMBER < 0x1010000fL))
    #define CRYSPR_NAME "OpenSSL_EVP-Fips"
    #define CRYSPR_HAS_FIPSMODE 1
    #else
    #define CRYSPR_NAME "OpenSSL-EVP"
    #error The OpenSSL cryspr FipsMode is supported for OpenSSL 1.0.1 and OpenSSL 1.0.2 distributions only
    #endif
#else
#define CRYSPR_NAME "OpenSSL"
#define CRYSPR_HAS_FIPSMODE 0
#endif

/* Define CRYSPR_HAS_AESCTR to 1 if this CRYSPR has AESCTR cipher mode
   if not set it 0 to use enable CTR cipher mode implementation using ECB cipher mode
   and provide the aes_ecb_cipher method.
*/
#define CRYSPR_HAS_AESCTR 1

/* Define CRYSPR_HAS_AESKWRAP to 1 if this CRYSPR has AES Key Wrap
   if not: set to 0 to enable default/fallback crysprFallback_AES_WrapKey/crysprFallback_AES_UnwrapKey methods
   and provide the aes_ecb_cipher method.
*/
#if CRYSPR_HAS_FIPSMODE
    //openSSLevp
    #if (OPENSSL_VERSION_NUMBER >= 0x1000200fL)
    //OpenSSL 1.0.2: Add EVP support for key wrapping algorithms
        #if 1
        //EVP_aes_NNN_wrap() envelop does not work in FIPS mode so don't use it.
        #define CRYSPR_HAS_AESKWRAP 0
        #else
        #define CRYSPR_HAS_AESKWRAP 1
        #endif
    #else
    #define CRYSPR_HAS_AESKWRAP 0
    #endif
#else /* CRYSPR_HAS_FIPSMODE */
    //openSSL
    #if (OPENSSL_VERSION_NUMBER >= 0x0090808fL)
    //0.9.8h //Add AES_wrap_key() and AES_unwrap_key() functions to implement RFC3394 compatible AES key wrapping
    #define CRYSPR_HAS_AESKWRAP 1
    #else
    #define CRYSPR_HAS_AESKWRAP 0
    #endif
#endif /* CRYSPR_HAS_FIPSMODE */

/* Define CRYSPR_HAS_PBKDF2 to 1 if this CRYSPR has SHA1-HMAC Password-based Key Derivaion Function 2
   if not set to 0 to enable not-yet-implemented/fallback crysprFallback.km_pbkdf2 method
   and provide the sha1_msg_digest method.
*/
#define CRYSPR_HAS_PBKDF2 1             /* Define to 1 if CRYSPR has Password-based Key Derivaion Function 2 */

/*
define CRYSPR_AESCTX to the CRYSPR specifix AES key context object.
It is the responsibility of the CRYSPR to reserve room statically in the control block
or dynamically in the open method, in both cases the cb pointers for KEK and SEK
must be set in the open method.
*/
#ifdef CRYSPR_FIPSMODE
/* FIPS mode with OpenSSL requires the use of the EVP (envelop) API */
typedef EVP_CIPHER_CTX CRYSPR_AESCTX;   /* CRYpto Service PRovider AES key context */
#else /* CRYSPR_FIPSMODE */
typedef AES_KEY CRYSPR_AESCTX;          /* CRYpto Service PRovider AES key context */
#endif /* CRYSPR_FIPSMODE */


struct tag_CRYSPR_methods *crysprOpenSSL(void);
struct tag_CRYSPR_methods *crysprOpenSSLevp(void);

#endif /* CRYSPR_OPENSSL_H */

