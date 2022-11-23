#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

#include "./include/common.h"

#define HASH EVP_sha256()

int sign_write(unsigned char *buf, int sz, FILE* outfp){
    int i;
    unsigned char *p = NULL;

    (void)i;
    (void)p;

    if (outfp != stdout){
        if (fwrite(buf, 1, sz, outfp) != sz){
            fprintf(stderr, "fwrite failed\n");
            return -1;
        }
        return sz;
    } else {
        p = &buf[0];
        for(i = 0;i < sz;i++){
            fprintf(outfp, "%02x", *p);
        }
        fprintf(outfp, "\n");
        return sz;
    }
}

int algo_main(int mode, FILE *fpKey, FILE *fpSig,
            unsigned char *key, int key_sz,
            unsigned char *iv,  int iv_sz,
            unsigned char *tag, int tag_sz
    ){
    
    EVP_PKEY   *pkey = NULL;
    EVP_MD_CTX *md = NULL;

    #define KEY_SIZE 2048
    unsigned char key_buff[KEY_SIZE];
    const unsigned char *key_p = key_buff;
    #define SIG_SIZE 256
    unsigned char sig[SIG_SIZE];
    #define BUFF_SIZE 256
    unsigned char msg[BUFF_SIZE];

    int inl;
    size_t sig_sz;
    int ret = SSL_FAILURE;

    if (mode >= 0 || fpKey == NULL || tag != NULL || key != NULL || iv != NULL) {
        fprintf(stderr, "ERROR: command argment\n");
    }

    if (fpSig == NULL){
        fpSig = stdout;
    }

    if ((key_sz = fread(key_buff, 1, sizeof(key_buff), fpKey)) < 0){
        fprintf(stderr, "ERROR: read key\n");
        return ret;
    }

    if ((pkey = d2i_PrivateKey(EVP_PKEY_DH, NULL, &key_p, key_sz)) == NULL){
        fprintf(stderr, "ERROR: d2i_PRivateKey\n");
        return ret;
    }

    if ((md = EVP_MD_CTX_new()) == NULL){
        fprintf(stderr, "ERROR: EVP_MD_CTX_new\n");
        return ret;
    }
    
    if (EVP_DigestSignInit(md, NULL, HASH, NULL, pkey) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: EVP_EncryptInit\n");
        return ret;
    }

    while(1){
        if ((inl = fread(msg, 1, BUFF_SIZE, stdin)) < 0){
            fprintf(stderr, "ERROR: fread\n");
            return ret;
        }
        EVP_DigestSignUpdate(md, msg, inl);
        if (inl < BUFF_SIZE){
            break;
        }
    }

    EVP_DigestSignFinal(md, sig, &sig_sz);
    sign_write(sig, sig_sz, fpSig);

    ret = SSL_SUCCESS;

    if (pkey != NULL){
        EVP_PKEY_free(pkey);
    }

    if (md != NULL){
        EVP_MD_CTX_free(md);
    }

    return ret;
}

