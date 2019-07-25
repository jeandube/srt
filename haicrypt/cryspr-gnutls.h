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

   2019-06-27 (jdube)
        GnuTLS/Nettle CRYSPR/4SRT (CRYypto Service PRovider for SRT)

*****************************************************************************/

#ifndef CRYSPR_GNUTLS_H
#define CRYSPR_GNUTLS_H

#include <gnutls/crypto.h>  //gnutls_rnd()

#include <nettle/aes.h>     //has AES cipher
#include <nettle/ctr.h>     //has CTR cipher mode
#include <nettle/pbkdf2.h>  //has Password-based Key Derivation Function 2
//#include <nettle/sha1.h>  //No need for sha1 since we have pbkdf2

#define CRYSPR_NAME "GnuTLS"

#ifdef CRYSPR_FIPSMODE
/* Define CRYSPR_HAS_FIPSMODE to 1 if this CRYSPR can operate in FIPS 140.2 mode.
*/
    #if ((GNUTLS_VERSION_NUMBER >= 0x030602))
    #define CRYSPR_NAME "GnuTLS-Fips"
    #define CRYSPR_HAS_FIPSMODE 1
    #else
    #error The GnuTLS cryspr FipsMode is supported for GnuTLS since 3.6.2 only
    #endif
#else
#define CRYSPR_NAME "GnuTLS"
#define CRYSPR_HAS_FIPSMODE 0
#endif


/* Define CRYSPR_HAS_AESCTR to 1 if this CRYSPR has AESCTR cipher mode
   if not set it 0 to use enable CTR cipher mode implementation using ECB cipher mode
   and provide the aes_ecb_cipher method.
*/
#define CRYSPR_HAS_AESCTR 1

/* Define CRYSPR_HAS_AESKWRAP to 1 if this CRYSPR has AES Key Wrap
   if not set to 0 to enable default/fallback crysprFallback_AES_WrapKey/crysprFallback_AES_UnwrapKey methods
   and provide the aes_ecb_cipher method  .
*/
#define CRYSPR_HAS_AESKWRAP 0

/* Define CRYSPR_HAS_PBKDF2 to 1 if this CRYSPR has SHA1-HMAC Password-based Key Derivaion Function 2
   if not set to 0 to enable not-yet-implemented/fallback crysprFallback.km_pbkdf2 method
   and provide the sha1_msg_digest method.
*/
#define CRYSPR_HAS_PBKDF2 1

/*
define CRYSPR_AESCTX to the CRYSPR specifix AES key context object.
It is the responsibility of the CRYSPR to reserve room statically in the control block
or dynamically in the open method, in both cases the cb pointers for KEK and SEK
must be set in the open method.
*/
typedef struct aes_ctx CRYSPR_AESCTX;   /* CRYpto Service PRovider AES key context */


struct tag_CRYSPR_methods *crysprGnuTLS(void);

#endif /* CRYSPR_GNUTLS_H */

