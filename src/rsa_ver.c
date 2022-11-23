#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

#include "./include/common.h"

#define HASH EVP_sha256()

int algo_main(int mode, FILE *fpPub, FILE *fpSig,
                 unsigned char *key, int key_sz,
                 unsigned char *iv, int iv_sz,
                 unsigned char *tag, int tag_sz)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md = NULL;
    #define KEY_BUFF 1024
    unsigned char pubkey[KEY_BUFF];
    const unsigned char *p = pubkey;
    #define SIG_SIZE 256
    unsigned char sig[SIG_SIZE];
    #define BUFF_SIZE 256
    unsigned char msg[BUFF_SIZE];

    int inl;
    size_t sig_sz;
    int ret = SSL_FAILURE;

    if (mode >= 0 || fpPub == NULL || fpSig == NULL 
        || tag != NULL || key != NULL || iv != NULL){
        fprintf(stderr, "ERROR: command argument\n");
        return ret;
    }

    if ((key_sz = fread(pubkey, 1, KEY_BUFF, fpPub)) < 0){
        fprintf(stderr, "ERROR: read key\n");
        return ret;
    }
    
    if ((sig_sz = fread(sig, 1, SIG_SIZE, fpSig)) < 0){
        fprintf(stderr, "ERROR: read signature\n");
        return ret;
    }
    printf("sig_sz: %d\n", sig_sz);


    if ((pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p, key_sz)) == NULL){
        fprintf(stderr, "ERROR: d2i_PublicKey\n");
        return ret;
    }

    if ((md = EVP_MD_CTX_new()) == NULL){
        fprintf(stderr, "ERROR: EVP_MD_CTX_new\n");
        return ret;
    }

    if (EVP_DigestVerifyInit(md, NULL, HASH, NULL, pkey) != SSL_SUCCESS){
        fprintf(stderr, "EVP_DigestVerifyInit\n");
        return ret;
    }

    while(1){
        if ((inl = fread(msg, 1, BUFF_SIZE, stdin)) < 0){
            fprintf(stderr, "ERROR: fread\n");
            return ret;
        }
        EVP_DigestVerifyUpdate(md, msg, inl);
        if (inl < BUFF_SIZE){
            break;
        }
    }

    if (EVP_DigestVerifyFinal(md, sig, sig_sz) == SSL_SUCCESS){
        printf("Signature Verified\n");
        ret = SSL_SUCCESS;
    } else {
        printf("Invalid Sginature\n");
    }

    if (pkey != NULL){
        EVP_PKEY_free(pkey);
    }
    if (md != NULL){
        EVP_MD_CTX_free(md);
    }

    return ret;
}