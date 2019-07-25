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

#include "hcrypt.h"

#include <string.h>

typedef struct tag_crysprGnuTLS_AES_cb {
        CRYSPR_cb       ccb;            /* mandatory 1st field CRYSPR control block */
        /* Add other cryptolib specific data here */
        struct aes_ctx  aes_kek_buf;    /* Room for KEK */
        struct aes_ctx  aes_sek_buf[2]; /* Room for odd and even SEKs */
        // More room allocated here and pointed to by ccb fields
        // ACtual size depends on CRYSPR supported features (CRYSPR_HAS_...)
} crysprGnuTLS_cb;

#if CRYSPR_HAS_FIPSMODE
static int crysprGnuTLS_FipsMode_get(void)
{
    int iOnOff = 0;

    unsigned uFipsMode = gnutls_fips140_mode_enabled();
    switch(uFipsMode) {
    case GNUTLS_FIPS140_STRICT:
         iOnOff = 1;
         break;
    case GNUTLS_FIPS140_LAX:
    case GNUTLS_FIPS140_LOG:
    case GNUTLS_FIPS140_DISABLED:
    case GNUTLS_FIPS140_SELFTESTS:
    default:
        break;
    }
    return(iOnOff);
}

static int crysprGnuTLS_FipsMode_set(bool bOnOff)
{
    unsigned uNewFipsMode = (bOnOff ? GNUTLS_FIPS140_STRICT : GNUTLS_FIPS140_LAX);
    unsigned uOldFipsMode = gnutls_fips140_mode_enabled();

    gnutls_fips140_set_mode (uNewFipsMode, 0);
    /* above function is no-op if FIPS is not supported,
       Verify by getting back state
    */
    if (uNewFipsMode != gnutls_fips140_mode_enabled()) {
        HCRYPT_LOG(LOG_ERR, "FIPS mode set %s\n", "failed");
        return(-1);
    }
    //return previous state
    return(((uOldFipsMode == GNUTLS_FIPS140_DISABLED) || (uOldFipsMode == GNUTLS_FIPS140_LAX)) ? 0 : 1);
}
#endif

int crysprGnuTLS_Prng(unsigned char *rn, int len)
{
    return(gnutls_rnd(GNUTLS_RND_KEY,(rn),(len)) < 0 ? -1 : 0);
}

int crysprGnuTLS_AES_SetKey(
    bool bEncrypt,              /* true:encrypt key, false:decrypt key*/
    const unsigned char *kstr,  /* key string */
    size_t kstr_len,            /* kstr length in  bytes (16, 24, or 32 bytes (for AES128,AES192, or AES256) */
    CRYSPR_AESCTX *aes_key)     /* Cryptolib Specific AES key context */
{
    if (bEncrypt) {        /* Encrypt key */
        if (!(kstr_len == 16 || kstr_len == 24 || kstr_len == 32)) {
            HCRYPT_LOG(LOG_ERR, "%s", "AES_set_encrypt_key(kek) bad length\n");
          return -1;
        }
        aes_set_encrypt_key (aes_key, kstr_len, kstr);
    } else {               /* Decrypt key */
        if (!(kstr_len == 16 || kstr_len == 24 || kstr_len == 32)) {
            HCRYPT_LOG(LOG_ERR, "%s", "AES_set_decrypt_key(kek) bad length\n");
          return -1;
        }
        aes_set_decrypt_key (aes_key, kstr_len, kstr);
    }
    return(0);
}

int crysprGnuTLS_AES_EcbCipher( /* AES Electronic Codebook cipher*/
    bool bEncrypt,              /* true:encrypt, false:decrypt */
    CRYSPR_AESCTX *aes_ctx,     /* CryptoLib AES context */
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
            aes_encrypt(aes_ctx, CRYSPR_AESBLKSZ, &out_txt[(i*CRYSPR_AESBLKSZ)], &indata[(i*CRYSPR_AESBLKSZ)]);
        }
        /* Encrypt last incomplete block */
        if (0 < nmore) {
            unsigned char intxt[CRYSPR_AESBLKSZ];

            memcpy(intxt, &indata[(nblk*CRYSPR_AESBLKSZ)], nmore);
            memset(intxt+nmore, 0, CRYSPR_AESBLKSZ-nmore);
            aes_encrypt(aes_ctx, CRYSPR_AESBLKSZ, &out_txt[(nblk*CRYSPR_AESBLKSZ)], intxt);
            nblk++;
        }
        if (outlen != NULL) *outlen = nblk*CRYSPR_AESBLKSZ;
    } else { /* Decrypt */
        for (i=0; i<nblk; i++){
            aes_decrypt(aes_ctx, CRYSPR_AESBLKSZ, &out_txt[(i*CRYSPR_AESBLKSZ)], &indata[(i*CRYSPR_AESBLKSZ)]);
        }
        /* Encrypt last incomplete block */
        if (0 < nmore) {
            //shall not happens in decrypt
        }
        if (outlen != NULL) *outlen = nblk*CRYSPR_AESBLKSZ;
    }
    return 0;
}

int crysprGnuTLS_AES_CtrCipher( /* AES-CTR128 Encryption */
    bool bEncrypt,              /* true:encrypt, false:decrypt */
    CRYSPR_AESCTX *aes_ctx,     /* CryptoLib AES context */
    unsigned char *iv,          /* iv */
    const unsigned char *indata,/* src */
    size_t inlen,               /* src length */
    unsigned char *out_txt)     /* dest buffer[inlen] */
{
    (void)bEncrypt;             /* CTR mode encrypt for both encryption and decryption */

    ctr_crypt (aes_ctx,         /* ctx */
               (nettle_cipher_func*)aes_encrypt, /* nettle_cipher_func */
               CRYSPR_AESBLKSZ,  /* cipher blocksize */
               iv,              /* iv */
               inlen,           /* length */
               out_txt,         /* dest */
               indata);         /* src */
    return 0;
}
static CRYSPR_cb *crysprGnuTLS_Open(CRYSPR_methods *cryspr, size_t pkt_maxlen)
{
    crysprGnuTLS_cb *gnuTLS_cb;

    gnuTLS_cb = (crysprGnuTLS_cb *)crysprAllocCB(sizeof(crysprGnuTLS_cb), pkt_maxlen);
    if (NULL == gnuTLS_cb) {
        HCRYPT_LOG(LOG_ERR, "crysprAllocCB(%zd,%zd) failed\n", sizeof(crysprGnuTLS_cb), pkt_maxlen);
        return(NULL);
    }
    /* Setup the CRYSPR control block key pointers */
    gnuTLS_cb->ccb.aes_kek = &gnuTLS_cb->aes_kek_buf;
    gnuTLS_cb->ccb.aes_sek[0] = &gnuTLS_cb->aes_sek_buf[0];
    gnuTLS_cb->ccb.aes_sek[1] = &gnuTLS_cb->aes_sek_buf[1];
    gnuTLS_cb->ccb.cryspr=cryspr;

    return((CRYSPR_cb *)gnuTLS_cb);
}

#ifdef CRYSPR_HAS_PBKDF2
/*
* Password-based Key Derivation Function
*/
int crysprGnuTLS_KmPbkdf2(
    CRYSPR_cb *cryspr_cb,
    char *passwd,           /* passphrase */
    size_t passwd_len,      /* passphrase len */
    unsigned char *salt,    /* salt */
    size_t salt_len,        /* salt_len */
    int itr,                /* iterations */
    size_t key_len,         /* key_len */
    unsigned char *out)     /* derived key buffer[key_len]*/
{
    (void)cryspr_cb;

    pbkdf2_hmac_sha1(passwd_len,(const uint8_t *)passwd,itr,salt_len,salt,key_len,out);
    return(0);
}
#endif /* CRYSPR_HAS_PBKDF2 */

static CRYSPR_methods crysprGnuTLS_methods;

CRYSPR_methods *crysprGnuTLS(void)
{
    if(NULL == crysprGnuTLS_methods.open) {
        crysprInit(&crysprGnuTLS_methods); /* Set default methods */

        /* CryptoLib Primitive API */
#if CRYSPR_HAS_FIPSMODE
        crysprGnuTLS_methods.fips_mode_set  = crysprGnuTLS_FipsMode_set;
#endif
        crysprGnuTLS_methods.prng           = crysprGnuTLS_Prng;
        crysprGnuTLS_methods.aes_set_key    = crysprGnuTLS_AES_SetKey;
    #if CRYSPR_HAS_AESCTR
        crysprGnuTLS_methods.aes_ctr_cipher = crysprGnuTLS_AES_CtrCipher;
    #endif
    #if !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP)
        /* AES-ECB only required if cryspr has no AES-CTR or no AES KeyWrap */
        crysprGnuTLS_methods.aes_ecb_cipher = crysprGnuTLS_AES_EcbCipher;
    #endif
    #if !CRYSPR_HAS_PBKDF2
        crysprGnuTLS_methods.sha1_msg_digest= crysprGnuTLS_SHA1_MsgDigest; //Onl required if using generic KmPbkdf2
    #endif

    //--Crypto Session (Top API)
        crysprGnuTLS_methods.open       = crysprGnuTLS_Open;
    //  crysprGnuTLS_methods.close      =
    //--Keying material (km) encryption
#if CRYSPR_HAS_PBKDF2
    	crysprGnuTLS_methods.km_pbkdf2  = crysprGnuTLS_KmPbkdf2;
#endif
    //	crysprGnuTLS_methods.km_setkey  =
    //  crysprGnuTLS_methods.km_wrap    =
    //  crysprGnuTLS_methods.km_unwrap  =
    //--Media stream (ms) encryption
    //  crysprGnuTLS_methods.ms_setkey  =
    //	crysprGnuTLS_methods.ms_encrypt =
    //	crysprGnuTLS_methods.ms_decrypt =
    }
    return(&crysprGnuTLS_methods);
}



