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
        OpenSSL CRYSPR/4SRT (CRYypto Service PRovider for SRT).
*****************************************************************************/

#include "hcrypt.h"
#ifndef CRYSPR_FIPSMODE

#include <string.h>


typedef struct tag_crysprOpenSSL_AES_cb {
        CRYSPR_cb       ccb;    /* Mandatory first field */
        AES_KEY aes_kek_buf;    /* Room for KEK */
        AES_KEY aes_sek_buf[2]; /* Room for odd and even SEKs */
        // More room allocated here and pointed to by ccb fields
        // ACtual size depends on CRYSPR supported features (CRYSPR_HAS_...)
} crysprOpenSSL_cb;


int crysprOpenSSL_Prng(unsigned char *rn, int len)
{
    return(RAND_bytes(rn, len) <= 0 ? -1 : 0);
}

static int crysprOpenSSL_AES_SetKey(
    bool bEncrypt,              /* true Enxcrypt key, false: decrypt */
    const unsigned char *kstr,  /* key sttring*/
    size_t kstr_len,            /* kstr len in  bytes (16, 24, or 32 bytes (for AES128,AES192, or AES256) */
    CRYSPR_AESCTX *aes_key)     /* CRYpto Service PRovider AES Key context */
{
    if (bEncrypt) {        /* Encrypt key */
        if (AES_set_encrypt_key(kstr, kstr_len * 8, aes_key)) {
            HCRYPT_LOG(LOG_ERR, "%s", "AES_set_encrypt_key(kek) failed\n");
            return(-1);
        }
    } else {               /* Decrypt key */
        if (AES_set_decrypt_key(kstr, kstr_len * 8, aes_key)) {
            HCRYPT_LOG(LOG_ERR, "%s", "AES_set_decrypt_key(kek) failed\n");
            return(-1);
        }
    }
    return(0);
}

#if !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP)

static int crysprOpenSSL_AES_EcbCipher(
    bool bEncrypt,              /* true:encrypt, false:decrypt */
    CRYSPR_AESCTX *aes_key,     /* CRYpto Service PRovider AES Key context */
    const unsigned char *indata,/* src (clear text)*/
    size_t inlen,               /* length */
    unsigned char *out_txt,     /* dst (cipher text) */
    size_t *outlen)             /* dst len */
{
    int nblk = inlen/CRYSPR_AESBLKSZ;
    int nmore = inlen%CRYSPR_AESBLKSZ;
    int i;

    if (bEncrypt) {
        /* Encrypt packet payload, block by block, in output buffer */
        for (i=0; i<nblk; i++){
            AES_ecb_encrypt(&indata[(i*CRYSPR_AESBLKSZ)],
                &out_txt[(i*CRYSPR_AESBLKSZ)], aes_key, AES_ENCRYPT);
        }
        /* Encrypt last incomplete block */
        if (0 < nmore) {
            unsigned char intxt[CRYSPR_AESBLKSZ];

            memcpy(intxt, &indata[(nblk*CRYSPR_AESBLKSZ)], nmore);
            memset(intxt+nmore, 0, CRYSPR_AESBLKSZ-nmore);
            AES_ecb_encrypt(intxt, &out_txt[(nblk*CRYSPR_AESBLKSZ)], aes_key, AES_ENCRYPT);
            nblk++;
        }
        if (outlen != NULL) *outlen = nblk*CRYSPR_AESBLKSZ;
    } else { /* Decrypt */
        for (i=0; i<nblk; i++){
            AES_ecb_encrypt(&indata[(i*CRYSPR_AESBLKSZ)],
                &out_txt[(i*CRYSPR_AESBLKSZ)], aes_key, AES_DECRYPT);
        }
        /* Encrypt last incomplete block */
        if (0 < nmore) {
            //shall not happens in decrypt
        }
        if (outlen != NULL) *outlen = nblk*CRYSPR_AESBLKSZ;
    }
    return 0;
}
#endif /* !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP) */

static int crysprOpenSSL_AES_CtrCipher(
    bool bEncrypt,              /* true:encrypt, false:decrypt */
    CRYSPR_AESCTX *aes_key,     /* CRYpto Service PRovider AES Key context */
    unsigned char *iv,          /* iv */
    const unsigned char *indata,/* src */
    size_t inlen,               /* length */
    unsigned char *out_txt)     /* dest */
{
    unsigned char ctr[CRYSPR_AESBLKSZ];
    unsigned blk_ofs = 0;
    (void)bEncrypt;             /* CTR mode encrypt for both encryption and decryption */

    memset(&ctr[0], 0, sizeof(ctr));
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(OPENSSL_IS_BORINGSSL))
    CRYPTO_ctr128_encrypt(indata, out_txt,
                          inlen, aes_key, iv, ctr, &blk_ofs, (block128_f) AES_encrypt);
#else
    AES_ctr128_encrypt(indata, out_txt,
                       inlen, aes_key, iv, ctr, &blk_ofs);
#endif
    return 0;
}

static CRYSPR_cb *crysprOpenSSL_Open(CRYSPR_methods *cryspr, size_t pkt_maxlen)
{
    crysprOpenSSL_cb *openSSL_cb;

    openSSL_cb = (crysprOpenSSL_cb *)crysprAllocCB(sizeof(crysprOpenSSL_cb), pkt_maxlen);
    if (NULL == openSSL_cb) {
        HCRYPT_LOG(LOG_ERR, "crysprAllocCB(%zd, %zd) failed\n", sizeof(crysprOpenSSL_cb), pkt_maxlen);
        return(NULL);
    }
    openSSL_cb->ccb.aes_kek = &openSSL_cb->aes_kek_buf;
    openSSL_cb->ccb.aes_sek[0] = &openSSL_cb->aes_sek_buf[0];
    openSSL_cb->ccb.aes_sek[1] = &openSSL_cb->aes_sek_buf[1];
    openSSL_cb->ccb.cryspr=cryspr;

    return((CRYSPR_cb *)openSSL_cb);
}

static int crysprOpenSSL_Close(CRYSPR_cb *cryspr_cb)
{
    crysprOpenSSL_cb *openSSL_cb = (crysprOpenSSL_cb *)cryspr_cb;

    if(openSSL_cb){
        OPENSSL_cleanse(&openSSL_cb->ccb.aes_kek, sizeof(openSSL_cb->ccb.aes_kek));
        OPENSSL_cleanse(&openSSL_cb->ccb.aes_sek, sizeof(openSSL_cb->ccb.aes_sek));
        crysprFreeCB(cryspr_cb);
        return(0);
    }
    return(-1);
}

/*
* Password-based Key Derivation Function
*/
int crysprOpenSSL_KmPbkdf2(
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

#if CRYSPR_HAS_AESKWRAP
static int crysprOpenSSL_KmWrap(CRYSPR_cb *cryspr_cb,
		unsigned char *wrap,
		const unsigned char *sek,
        unsigned int seklen)
{
    AES_KEY *kek = cryspr_cb->aes_kek; //key encrypting key

    return(((seklen + HAICRYPT_WRAPKEY_SIGN_SZ) == (unsigned int)AES_wrap_key(kek, NULL, wrap, sek, seklen)) ? 0 : -1);
}

static int crysprOpenSSL_KmUnwrap(
        CRYSPR_cb *cryspr_cb,
		unsigned char *sek,             //Stream encrypting key
		const unsigned char *wrap,
        unsigned int wraplen)
{
    AES_KEY *kek = cryspr_cb->aes_kek; //key encrypting key

    return(((wraplen - HAICRYPT_WRAPKEY_SIGN_SZ) == (unsigned int)AES_unwrap_key(kek, NULL, sek, wrap, wraplen)) ? 0 : -1);
}
#endif /*CRYSPR_HAS_AESKWRAP*/


static CRYSPR_methods crysprOpenSSL_methods;

CRYSPR_methods *crysprOpenSSL(void)
{
    if(NULL == crysprOpenSSL_methods.open) {
        crysprInit(&crysprOpenSSL_methods);    //Default/fallback methods

        crysprOpenSSL_methods.prng           = crysprOpenSSL_Prng;
    //--CryptoLib Primitive API-----------------------------------------------
        crysprOpenSSL_methods.aes_set_key    = crysprOpenSSL_AES_SetKey;
    #if CRYSPR_HAS_AESCTR
        crysprOpenSSL_methods.aes_ctr_cipher = crysprOpenSSL_AES_CtrCipher;
    #endif
    #if !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP)
        /* AES-ECB only required if cryspr has no AES-CTR and no AES KeyWrap */
        /* OpenSSL has both AESCTR and AESKWRP and the AESECB wrapper is only used
           to test the falback methods */
        crysprOpenSSL_methods.aes_ecb_cipher = crysprOpenSSL_AES_EcbCipher;
    #endif
    #if !CRYSPR_HAS_PBKDF2
        crysprOpenSSL_methods.sha1_msg_digest= NULL; //Required to use eventual default/fallback KmPbkdf2
    #endif

    //--Crypto Session API-----------------------------------------
        crysprOpenSSL_methods.open     = crysprOpenSSL_Open;
        crysprOpenSSL_methods.close    = crysprOpenSSL_Close;
    //--Keying material (km) encryption

#if CRYSPR_HAS_PBKDF2
    	crysprOpenSSL_methods.km_pbkdf2  = crysprOpenSSL_KmPbkdf2;
#else
#error  There is no default/fallback method for PBKDF2
#endif
    //	crysprOpenSSL_methods.km_setkey  =
#if CRYSPR_HAS_AESKWRAP
        crysprOpenSSL_methods.km_wrap    = crysprOpenSSL_KmWrap;
        crysprOpenSSL_methods.km_unwrap  = crysprOpenSSL_KmUnwrap;
#endif

    //--Media stream (ms) encryption
    //  crysprOpenSSL_methods.ms_setkey  =
    //	crysprOpenSSL_methods.ms_encrypt =
    //	crysprOpenSSL_methods.ms_decrypt =
    }
    return(&crysprOpenSSL_methods);
}
#endif /* CRYSPR_FIPSMODE */

