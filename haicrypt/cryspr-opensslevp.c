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
        OpenSSL EVP CRYSPR/4SRT (CRYypto Service PRovider for SRT).
        EVP API required to support FIPS 140-2 mode.
*****************************************************************************/

#include "hcrypt.h"
#include <string.h>
#include <errno.h>

#ifdef CRYSPR_FIPSMODE

typedef struct tag_crysprOpenSSLevp_cb {
        CRYSPR_cb       ccb;

} crysprOpenSSLevp_cb;

static CRYSPR_methods crysprFallback_methods;

static int crysprOpenSSLevp_FipsMode_get(void)
{
    int iFipsMode = FIPS_mode();
    return(iFipsMode); /*1: set, 0:unset */
}

static int crysprOpenSSLevp_FipsMode_set(bool OnOff)
{
    int iOnOff = (OnOff ? 1 : 0);
    int iPreState = FIPS_mode();


    if( iPreState != iOnOff) {
        int rc = FIPS_mode_set(iOnOff);
        if (rc == 0) {
            char szErrStr[80] = "";
            unsigned long ulErrc = ERR_get_error();
            ERR_error_string_n(ulErrc, szErrStr, sizeof(szErrStr));
            HCRYPT_LOG(LOG_ERR, "FIPS_mode_set failed: %s\n", szErrStr);
            return(-1);
        }
    } else {
        ;//desired state already set
    }
    return(iPreState ? 1 : 0);
}

int crysprOpenSSLevp_Prng(unsigned char *rn, int len)
{
    return(RAND_bytes(rn, len) <= 0 ? -1 : 0);
}

int crysprOpenSSLevp_AES_SetKey(
    bool bEncrypt,              /* true Enxcrypt key, false: decrypt */
    const unsigned char *kstr,  /* key sttring*/
    size_t kstr_len,            /* kstr len in  bytes (16, 24, or 32 bytes (for AES128,AES192, or AES256) */
    CRYSPR_AESCTX *aes_ctx)     /* CRYpto Service PRovider AES Key context */
{
    EVP_CIPHER_CTX *evp_ctx = (EVP_CIPHER_CTX *)aes_ctx;
    (void)kstr_len;
    const EVP_CIPHER *cipher = NULL;
    int enc = (bEncrypt ? 1 : 0);

    if(evp_ctx == NULL) {
        HCRYPT_LOG(LOG_ERR, "%s\n", "NULL key context");
        return(-1);
    }
    switch(kstr_len) {
#if CRYSPR_HAS_AESCTR
    case 128/8:
        cipher = EVP_aes_128_ctr();
        break;
    case 192/8:
        cipher = EVP_aes_192_ctr();
        break;
    case 256/8:
        cipher = EVP_aes_256_ctr();
        break;
#else /* CRYSPR_HAS_AESCTR */
    case 128/8:
        cipher = EVP_aes_128_ecb();
        break;
    case 192/8:
        cipher = EVP_aes_192_ecb();
        break;
    case 256/8:
        cipher = EVP_aes_256_ecb();
        break;
#endif /* CRYSPR_HAS_AESCTR */
    default:
        HCRYPT_LOG(LOG_ERR, "invalid key length (%d). Expected: 16, 24, 32\n", (int)kstr_len);
        return(-1);
    }

    if(!EVP_CipherInit_ex(evp_ctx, cipher, NULL, kstr, NULL, enc)){
        HCRYPT_LOG(LOG_ERR, "EVP_CipherInit_ex(EVP_aes_%d_%s) failed\n", (int)kstr_len*8,
#if CRYSPR_HAS_AESCTR
        "_ctr");
#else
        "_ecb");
#endif
        EVP_CIPHER_CTX_cleanup(evp_ctx);
        return(-1);
    }
    return(0);
}


static CRYSPR_cb *crysprOpenSSLevp_Open(CRYSPR_methods *cryspr, size_t max_len)
{
    CRYSPR_cb *cryspr_cb;
    EVP_CIPHER_CTX *evp_ctx;
    cryspr_cb = crysprFallback_methods.open(cryspr, max_len);
    if(NULL == cryspr_cb) return(cryspr_cb);

    evp_ctx = EVP_CIPHER_CTX_new();
    if(NULL == evp_ctx) {
        crysprFallback_methods.close(cryspr_cb);
        return(NULL);
    }
    cryspr_cb->aes_kek = evp_ctx;

    evp_ctx = EVP_CIPHER_CTX_new();
    if(NULL == evp_ctx) {
        crysprFallback_methods.close(cryspr_cb);
        return(NULL);
    }
    EVP_CIPHER_CTX_set_padding(evp_ctx, 0);
    cryspr_cb->aes_sek[0] = (void *)evp_ctx;

    evp_ctx = EVP_CIPHER_CTX_new();
    if(NULL == evp_ctx) {
        crysprFallback_methods.close(cryspr_cb);
        return(NULL);
    }
    EVP_CIPHER_CTX_set_padding(evp_ctx, 0);
    cryspr_cb->aes_sek[1] = evp_ctx;
    return(cryspr_cb);
}

static int crysprOpenSSLevp_Close(CRYSPR_cb *cryspr_cb)
{
    if (NULL != cryspr_cb) {
        if(cryspr_cb->aes_sek[1] != NULL) {
            OPENSSL_cleanse(&cryspr_cb->aes_sek[1], sizeof(cryspr_cb->aes_sek[1]));
            EVP_CIPHER_CTX_free(cryspr_cb->aes_sek[1]);
        }
        if(cryspr_cb->aes_sek[0] != NULL) {
            OPENSSL_cleanse(&cryspr_cb->aes_sek[0], sizeof(cryspr_cb->aes_sek[1]));
            EVP_CIPHER_CTX_free(cryspr_cb->aes_sek[0]);
        }
        if(cryspr_cb->aes_kek != NULL) {
            OPENSSL_cleanse(&cryspr_cb->aes_kek, sizeof(cryspr_cb->aes_kek));
            EVP_CIPHER_CTX_free(cryspr_cb->aes_kek);
        }
        crysprFallback_methods.close(cryspr_cb);
    }
    return(0);
}

#if !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP)

int crysprOpenSSLevp_AES_EcbCipher(
    bool bEncrypt,              /* true:encrypt, false:decrypt */
    CRYSPR_AESCTX *aes_ctx,     /* CRYpto Service PRovider AES Key context */
    const unsigned char *indata,/* src (clear text)*/
    size_t inlen,               /* length */
    unsigned char *out_txt,     /* dst (cipher text) */
    size_t *outlen)             /* dst len */
{
    int c_len, f_len;
    EVP_CIPHER_CTX *evp_ctx = (EVP_CIPHER_CTX *)aes_ctx;
    (void)bEncrypt;

    if(evp_ctx == NULL) {
        HCRYPT_LOG(LOG_ERR, "%s.\n", "NULL key context.");
        return(-1);
    }
    if (bEncrypt && !evp_ctx->encrypt) {
        //inconsitent key context: must be encrypting key
        errno = EINVAL;
        return(-1);
    }
    /* allows reusing of 'e' for multiple encryption cycles */
    EVP_CipherInit_ex(evp_ctx, NULL, NULL, NULL, NULL, -1);
    EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
     * cryptoPtr->cipher_in_len is the size of plain/cipher text in bytes
     */
    EVP_CipherUpdate(evp_ctx, out_txt, &c_len, indata, inlen);

    /* update ciphertext with the final remaining bytes */
    /* Useless with pre-padding */
    f_len = 0;
    if (0 == EVP_CipherFinal_ex(evp_ctx, &out_txt[c_len], &f_len)) {
        HCRYPT_LOG(LOG_ERR, "incomplete block (%d/%zd)\n", c_len, inlen);
    }
    if (outlen) *outlen = c_len + f_len;
    return(0);
}
#endif /* !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP) */

int crysprOpenSSLevp_AES_CtrCipher(
    bool bEncrypt,              /* true:encrypt, false:decrypt */
    CRYSPR_AESCTX *aes_ctx,     /* CRYpto Service PRovider AES Key context */
    unsigned char *iv,          /* iv */
    const unsigned char *indata,/* src */
    size_t inlen,               /* length */
    unsigned char *out_txt)     /* dest */
{
    EVP_CIPHER_CTX *evp_ctx = (EVP_CIPHER_CTX *)aes_ctx;
    int c_len;
    int f_len = 0;
    int rc = 0;

    (void)bEncrypt;

    if(evp_ctx == NULL) {
        HCRYPT_LOG(LOG_ERR, "%s.\n", "NULL key context");
        return(-1);
    }
    if (bEncrypt && !evp_ctx->encrypt) {
        HCRYPT_LOG(LOG_ERR, "%s.\n", "inconsitent key context: must be encrypting key");
        rc = -1;
    }
    /* allows reusing of 'e' for multiple encryption cycles */
    else if(!EVP_CipherInit_ex(evp_ctx, NULL, NULL, NULL, iv, -1)) {
        HCRYPT_LOG(LOG_ERR, "%s.\n", "EVP_CipherInit_ex failed");
        rc = -1;
    }
    else if(!EVP_CIPHER_CTX_set_padding(evp_ctx, 0)) {
        ;//should not happen: always return 1
    }

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
     * cryptoPtr->cipher_in_len is the size of plain/cipher text in bytes
     */
    else if(!EVP_CipherUpdate(evp_ctx, out_txt, &c_len, indata, inlen)){
        HCRYPT_LOG(LOG_ERR, "%s.\n", "EVP_CipherUpdate failed");
        rc = -1;
    }

    /* update ciphertext with the final remaining bytes */
    /* Useless with pre-padding */
    else if (!EVP_CipherFinal_ex(evp_ctx, &out_txt[c_len], &f_len)) {
        HCRYPT_LOG(LOG_ERR, "incomplete block (%d/%zd)\n", c_len, inlen);
        rc = -1;
    }
    EVP_CIPHER_CTX_cleanup(evp_ctx);
    return(rc);
}

/*
* Password-based Key Derivation Function
*/
int crysprOpenSSLevp_KmPbkdf2(
    CRYSPR_cb *cryspr_cb,
    char *passwd,           /* passphrase */
    size_t passwd_len,      /* passphrase len */
    unsigned char *salt,    /* salt */
    size_t salt_len,        /* salt_len */
    int itr,                /* iterations */
    size_t key_len,         /* key_len */
    unsigned char *out)     /* derived key */
{
    (void)cryspr_cb;
    int rc = PKCS5_PBKDF2_HMAC_SHA1(passwd,passwd_len,salt,salt_len,itr,key_len,out);
    return(rc == 1? 0 : -1);
}

static int crysprOpenSSLevp_KmSetKey(CRYSPR_cb *cryspr_cb, bool bWrap, const unsigned char *kstr, size_t kstr_len)
{
    EVP_CIPHER_CTX *evp_ctx = cryspr_cb->aes_kek;
    (void)kstr_len;
    const EVP_CIPHER *cipher = NULL;
    int enc = bWrap ? 1 : 0; //1:encrypt, 0:decrypt, -1:keep previous setting

    if(evp_ctx == NULL) {
        HCRYPT_LOG(LOG_ERR, "%s.\n", "NULL key context");
        return(-1);
    }
    switch(kstr_len) {
#if CRYSPR_HAS_AESKWRAP
    case 128/8:
        cipher = EVP_aes_128_wrap();
        break;
    case 192/8:
        cipher = EVP_aes_192_wrap();
        break;
    case 256/8:
        cipher = EVP_aes_256_wrap();
        break;
#else /* CRYSPR_HAS_AESKWRAP */
    case 128/8:
        cipher = EVP_aes_128_ecb();
        break;
    case 192/8:
        cipher = EVP_aes_192_ecb();
        break;
    case 256/8:
        cipher = EVP_aes_256_ecb();
        break;
#endif /* CRYSPR_HAS_AESKWRAP */
    default:
        HCRYPT_LOG(LOG_ERR, "invalid key length (%d). Expected: 16, 24, 32\n", (int)kstr_len);
        return(-1);
    }
#if CRYSPR_HAS_AESKWRAP
    EVP_CIPHER_CTX_set_flags(evp_ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
#endif
    if(!EVP_CipherInit_ex(evp_ctx, cipher, NULL, kstr, NULL, enc)) {
        HCRYPT_LOG(LOG_ERR, "%s failed.\n", "EVP_CipherInit_ex");
        EVP_CIPHER_CTX_cleanup(evp_ctx);
        return(-1);
    }
    return(0);
}

#if CRYSPR_HAS_AESKWRAP
#if CRYSPR_FIPSMODE
#error EVP_aes_NNN_wrap does not works in FIPS mode set
#endif

int crysprOpenSSLevp_KmWrap(CRYSPR_cb *cryspr_cb,
		unsigned char *wrap,
		const unsigned char *sek,
        unsigned int seklen)
{
    EVP_CIPHER_CTX *evp_ctx = cryspr_cb->aes_kek;
    int c_len, f_len;

    if(evp_ctx == NULL) {
        HCRYPT_LOG(LOG_ERR, "%s.\n", "NULL key context");
        EVP_CIPHER_CTX_cleanup(evp_ctx);
        return(-1);
    }
    /* allows reusing of 'e' for multiple encryption cycles */
    if (!EVP_CipherInit_ex(evp_ctx, NULL, NULL, NULL, NULL, -1)){
        HCRYPT_LOG(LOG_ERR, "%s failed.\n", "EVP_CipherInit_ex()");
        EVP_CIPHER_CTX_cleanup(evp_ctx);
        return(-1);
    }
    EVP_CIPHER_CTX_set_flags(evp_ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
     * cryptoPtr->cipher_in_len is the size of plain/cipher text in bytes
     */
    if(!EVP_CipherUpdate(evp_ctx, wrap, &c_len, sek, seklen)) {
        HCRYPT_LOG(LOG_ERR, "%s failed.\n", "EVP_CipherUpdate()");
        EVP_CIPHER_CTX_cleanup(evp_ctx);
        return(-1);
    }

    /* update ciphertext with the final remaining bytes */
    /* Useless with pre-padding */
    f_len = 0;
    if (!EVP_CipherFinal_ex(evp_ctx, &wrap[c_len], &f_len)) {
        HCRYPT_LOG(LOG_ERR, "incomplete block (%d/%zd)\n", c_len, seklen);
        EVP_CIPHER_CTX_cleanup(evp_ctx);
        return(-1);
    }

    EVP_CIPHER_CTX_cleanup(evp_ctx);
    return(0);
}
#endif /*CRYSPR_HAS_AESKWRAP*/

static CRYSPR_methods crysprOpenSSLevp_methods;

CRYSPR_methods *crysprOpenSSLevp(void)
{
    if(NULL == crysprOpenSSLevp_methods.open) {
        crysprInit(&crysprOpenSSLevp_methods);    //Default/fallback methods

        //grab the default methods for customized Open/Close
        memcpy(&crysprFallback_methods, &crysprOpenSSLevp_methods, sizeof(CRYSPR_methods));

        crysprOpenSSLevp_methods.fips_mode_get  = crysprOpenSSLevp_FipsMode_get;
        crysprOpenSSLevp_methods.fips_mode_set  = crysprOpenSSLevp_FipsMode_set;
        crysprOpenSSLevp_methods.prng           = crysprOpenSSLevp_Prng;
    //--CryptoLib Primitive API-----------------------------------------------
        crysprOpenSSLevp_methods.aes_set_key    = crysprOpenSSLevp_AES_SetKey;
    #if CRYSPR_HAS_AESCTR
        crysprOpenSSLevp_methods.aes_ctr_cipher = crysprOpenSSLevp_AES_CtrCipher;
    #endif
    #if !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP)
        /* AES-ECB only required if cryspr has no AES-CTR and no AES KeyWrap */
        /* OpenSSL has both AESCTR and AESKWRP and the AESECB wrapper is only used
           to test the falback methods */
        crysprOpenSSLevp_methods.aes_ecb_cipher = crysprOpenSSLevp_AES_EcbCipher;
    #endif
    #if !CRYSPR_HAS_PBKDF2
        crysprOpenSSLevp_methods.sha1_msg_digest= NULL; //Required to use eventual default/fallback KmPbkdf2
    #endif

    //--Crypto Session API-----------------------------------------
        crysprOpenSSLevp_methods.open     = crysprOpenSSLevp_Open;
        crysprOpenSSLevp_methods.close    = crysprOpenSSLevp_Close;
    //--Keying material (km) encryption

#if CRYSPR_HAS_PBKDF2
        // No EVP API for PBKDF2, reuse OpenSSL(AES) cryspr implemenation
        crysprOpenSSLevp_methods.km_pbkdf2  = crysprOpenSSLevp_KmPbkdf2;
#else
#error  There is no default/fallback method for PBKDF2
#endif
        crysprOpenSSLevp_methods.km_setkey  = crysprOpenSSLevp_KmSetKey;
#if CRYSPR_HAS_AESKWRAP
        crysprOpenSSLevp_methods.km_wrap    = crysprOpenSSLevp_KmWrap;
        crysprOpenSSLevp_methods.km_unwrap  = crysprOpenSSLevp_KmWrap; //Wrap/Unwrap defined in KmSetKey use same Wrap fct
#endif

    //--Media stream (ms) encryption
    //  crysprOpenSSL_methods.ms_setkey  =
    //	crysprOpenSSL_methods.ms_encrypt =
    //	crysprOpenSSL_methods.ms_decrypt =
    }
    return(&crysprOpenSSLevp_methods);
}

#endif /* CRYSPR_FIPSMODE */

