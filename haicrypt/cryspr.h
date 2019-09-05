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

   2019-06-28 (jdube)
        CRYSPR/4SRT Initial implementation.
*****************************************************************************/

#ifndef CRYSPR_H
#define CRYSPR_H

#include <stdbool.h>
#include <sys/types.h>

#if !defined(HAISRT_VERSION_INT)
#include "haicrypt.h"
#include "hcrypt_msg.h"
#else
// Included by haisrt.h or similar
#include "haisrt/haicrypt.h"
#include "haisrt/hcrypt_msg.h"
#endif

/*
CRYSPR_VERSION_NUMBER
    1.0.0: unidentified initial version for mbedTLS support
    1.1.0: FIPS mode support (FIPS 140-2) for openssl and GnuTLS
 */
#define CRYSPR_VERSION_NUMBER  0x010100    /* 1.1.0 */

#if (CRYSPR_VERSION_NUMBER >= 0x010100)
#define CRYSPR_FIPSMODE 0
#endif

#if defined(USE_OPENSSL)
#include "cryspr-openssl.h"
#if defined CRYSPR_FIPSMODE
#define cryspr4SRT()  crysprOpenSSLevp()
#else
#define cryspr4SRT()  crysprOpenSSL()
#endif

#elif defined(USE_GNUTLS)
#include "cryspr-gnutls.h"
#define cryspr4SRT()  crysprGnuTLS()
#else
#error No CRYSPR defined
#endif


#define CRYSPR_AESBLKSZ 16          /* 128-bit */

typedef struct tag_CRYSPR_cb {
    CRYSPR_AESCTX *aes_kek;         /* Key Encrypting Key (KEK) */
    CRYSPR_AESCTX *aes_sek[2];      /* even/odd Stream Encrypting Key (SEK) */

    struct tag_CRYSPR_methods *cryspr;

#if !CRYSPR_HAS_AESCTR
                                    /* Reserve room to build the counter stream ourself */
#define HCRYPT_CTR_BLK_SZ       CRYSPR_AESBLKSZ
#define HCRYPT_CTR_STREAM_SZ	2048
    unsigned char * ctr_stream;
    size_t          ctr_stream_len; /* Content size */
    size_t          ctr_stream_siz; /* Allocated length */
#endif /* !CRYSPR_HAS_AESCTR */

#define	CRYSPR_OUTMSGMAX		6
    uint8_t *       outbuf;         /* output circle buffer */
    size_t          outbuf_ofs;     /* write offset in circle buffer */
    size_t          outbuf_siz;     /* circle buffer size */
} CRYSPR_cb;

            /*
            * fips_mode_get:
            * Get Crypto library FIPS 140-2 mode of operation
            * returns:
            *   0: Off, unset, unsupported,
            *   1: On
            */
typedef int (*CRYSPR_FIPSMODE_GET_FCT)(void);

            /*
            * fips_mode_set:
            * Set (bOnOff=true) or unset(bOnOff=false) Crypto library FIPS 140-2 mode of operation
            * FIPS mode may be preset at compile time or not be supported at allby underlying CRYSPR
            * returns:
            *  -1: error,
            *   0: success, previous state was Off
            *   1: success, previous state was On
            */
typedef int (*CRYSPR_FIPSMODE_SET_FCT)(bool bOnOff);

            /*
            * prng:
            * Pseudo-Random Number Generator
            */
typedef int (*CRYSPR_PRNG_FCT)(unsigned char *rn, int rn_len);

typedef int (*CRYSPR_AES_SET_KEY_FCT)(
            bool bEncrypt,          /* true Enxcrypt key, false: decrypt */
            const unsigned char *kstr,/* key string*/
            size_t kstr_len,        /* kstr len in  bytes (16, 24, or 32 bytes (for AES128,AES192, or AES256) */
            CRYSPR_AESCTX *aes_key);/* Cryptolib Specific AES key context */

typedef int (*CRYSPR_AES_ECB_CIPHER_FCT)(
            bool bEncrypt,          /* true:encrypt false:decrypt */
            CRYSPR_AESCTX *aes_key, /* ctx */
            const unsigned char *indata,  /* src (clear text)*/
            size_t inlen,           /* src length */
            unsigned char *out_txt, /* dst (cipher text) */
            size_t *outlen);        /* dst length */

typedef int (*CRYSPR_AES_CTR_CIPHER_FCT)(
            bool bEncrypt,          /* true:encrypt false:decrypt (don't care with CTR) */
            CRYSPR_AESCTX *aes_key, /* ctx */
            unsigned char *iv,      /* iv */
            const unsigned char *indata,  /* src (clear text) */
            size_t inlen,           /* src length */
            unsigned char *out_txt);/* dest */

typedef unsigned char *(*CRYSPR_SHA1_MSG_DIGEST_FCT)(
            const unsigned char *m, /* in: message */
            size_t m_len,           /* message length */
            unsigned char *md);     /* out: message digest buffer *160 bytes */

typedef CRYSPR_cb *(*CRYSPR_OPEN_FCT)(
            struct tag_CRYSPR_methods *cryspr,
            size_t max_len);        /* Maximum packet length that will be encrypted/decrypted */

typedef int (*CRYSPR_CLOSE_FCT)(
            CRYSPR_cb *cryspr_data);/* Cipher handle, internal data */

typedef int (*CRYSPR_KM_PBKDF2_FCT)(
            CRYSPR_cb *cryspr_cb,   /* Cryspr Control Block */
            char *passwd,           /* passphrase */
            size_t passwd_len,      /* passphrase len */
            unsigned char *salt,    /* salt */
            size_t salt_len,        /* salt_len */
            int itr,                /* iterations */
            size_t out_len,         /* key_len */
            unsigned char *out);    /* derived key */

            /*
            * km_setkey:
            * Set the Key Encypting Key for Wrap (Encryption) or UnWrap (Decryption).
            * Context (ctx) tells if it's for Wrap or Unwrap
            * A Context flags (ctx->flags) also tells if this is for wrap(encryption) or unwrap(decryption) context (HCRYPT_CTX_F_ENCRYPT)
            */
typedef int (*CRYSPR_KM_SETKEY_FCT)(
            CRYSPR_cb *cryspr_cb,                       /* Cryspr Control Block */
            bool bWrap,                                 /* True: Wrap KEK, False: Unwrap KEK */
            const unsigned char *kek, size_t kek_len);  /* KEK: Key Encrypting Key */

typedef int (*CRYSPR_KM_WRAP_FCT)(CRYSPR_cb *cryspr_cb,
            unsigned char *wrap,
            const unsigned char *sek,
            unsigned int seklen);

typedef int (*CRYSPR_KM_UNWRAP_FCT)(CRYSPR_cb *cryspr_cb,
            unsigned char *sek,
            const unsigned char *wrap,
            unsigned int wraplen);

            /*
            * setkey:
            * Set the Odd or Even, Encryption or Decryption key.
            * Context (ctx) tells if it's for Odd or Even key (hcryptCtx_GetKeyIndex(ctx))
            * A Context flags (ctx->flags) also tells if this is an encryption or decryption context (HCRYPT_CTX_F_ENCRYPT)
            */
typedef int (*CRYSPR_MS_SETKEY_FCT)(
            CRYSPR_cb *cryspr_cb,                           /* Cryspr Control Block */
            hcrypt_Ctx *ctx,                                /* HaiCrypt Context (cipher, keys, Odd/Even, etc..) */
            const unsigned char *key, size_t kwelen);       /* New Key */

            /*
            * encrypt:
            * Submit a list of nbin clear transport packets (hcrypt_DataDesc *in_data) to encryption
            * returns *nbout encrypted data packets of length out_len_p[] into out_p[]
            *
            * If cipher implements deferred encryption (co-processor, async encryption),
            * it may return no encrypted packets, or encrypted packets for clear text packets of a previous call.
            */
typedef int (*CRYSPR_MS_ENCRYPT_FCT)(
            CRYSPR_cb *cryspr_cb,                           /* Cryspr Control Block */
            hcrypt_Ctx *ctx,                                /* HaiCrypt Context (cipher, keys, Odd/Even, etc..) */
            hcrypt_DataDesc *in_data, int nbin,             /* Clear text transport packets: header and payload */
            void *out_p[], size_t out_len_p[], int *nbout); /* Encrypted packets */

            /*
            * decrypt:
            * Submit a list of nbin encrypted transport packets (hcrypt_DataDesc *in_data) to decryption
            * returns *nbout clear text data packets of length out_len_p[] into out_p[]
            *
            * If cipher implements deferred decryption (co-processor, async encryption),
            * it may return no decrypted packets, or decrypted packets for encrypted packets of a previous call.
            */
typedef int (*CRYSPR_MS_DECRYPT_FCT)(
            CRYSPR_cb *cryspr_cb,                           /* Cryspr Control Block */
            hcrypt_Ctx *ctx,                                /* HaiCrypt Context (cipher, keys, Odd/Even, etc..) */
            hcrypt_DataDesc *in_data, int nbin,             /* Clear text transport packets: header and payload */
            void *out_p[], size_t out_len_p[], int *nbout); /* Encrypted packets */


typedef struct tag_CRYSPR_methods {
        CRYSPR_FIPSMODE_GET_FCT fips_mode_get;
        CRYSPR_FIPSMODE_SET_FCT fips_mode_set;
        CRYSPR_PRNG_FCT prng;

        CRYSPR_AES_SET_KEY_FCT aes_set_key;
        CRYSPR_AES_ECB_CIPHER_FCT aes_ecb_cipher;
        CRYSPR_AES_CTR_CIPHER_FCT aes_ctr_cipher;

        CRYSPR_SHA1_MSG_DIGEST_FCT sha1_msg_digest;

        /*
        * open:
        * Create a cipher instance
        * Allocate output buffers
        */
        CRYSPR_OPEN_FCT open;

        /*
        * close:
        * Release any cipher resources
        */
        CRYSPR_CLOSE_FCT close;

        /*
        * pbkdf2_hmac_sha1
        * Password-based Key Derivation Function 2
        */
        CRYSPR_KM_PBKDF2_FCT km_pbkdf2;

        /*
        * km_setkey:
        * Set the Key Encypting Key for Wrap (Encryption) or UnWrap (Decryption).
        * Context (ctx) tells if it's for Wrap or Unwrap
        * A Context flags (ctx->flags) also tells if this is for wrap(encryption) or unwrap(decryption) context (HCRYPT_CTX_F_ENCRYPT)
        */
        CRYSPR_KM_SETKEY_FCT km_setkey;

        /*
        * km_wrap/unwrap:
        * wrap/unwrap media stream key
        */
        CRYSPR_KM_WRAP_FCT km_wrap;
        CRYSPR_KM_UNWRAP_FCT km_unwrap;

        /*
        * setkey:
        * Set the Odd or Even, Encryption or Decryption key.
        * Context (ctx) tells if it's for Odd or Even key (hcryptCtx_GetKeyIndex(ctx))
        * A Context flags (ctx->flags) also tells if this is an encryption or decryption context (HCRYPT_CTX_F_ENCRYPT)
        */
        CRYSPR_MS_SETKEY_FCT ms_setkey;

        /*
        * encrypt:
        * Submit a list of nbin clear transport packets (hcrypt_DataDesc *in_data) to encryption
        * returns *nbout encrypted data packets of length out_len_p[] into out_p[]
        *
        * If cipher implements deferred encryption (co-processor, async encryption),
        * it may return no encrypted packets, or encrypted packets for clear text packets of a previous call.  
        */
        CRYSPR_MS_ENCRYPT_FCT ms_encrypt;

        CRYSPR_MS_DECRYPT_FCT ms_decrypt;

} CRYSPR_methods;

CRYSPR_methods *crysprInit(CRYSPR_methods *cryspr);
CRYSPR_cb *     crysprAllocCB(size_t extra_len, size_t pkt_maxlen);
void            crysprFreeCB(CRYSPR_cb *cryspr_cb);
int             crysprFipsModeInit(void);
int             crysprFipsModeSet(bool bOnOff);

#endif /* CRYSPR_H */
