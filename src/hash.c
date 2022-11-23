#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "include/common.h"
#include "include/algo_main.h"

#define BUFF_SIZE 16

int algo_main(int mode, FILE *infp, FILE *outfp,
        unsigned char *key, int key_sz,
        unsigned char *iv, int iv_sz,
        unsigned char *tag, int tag_sz){
    char in[BUFF_SIZE];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int inl;
    int i;
    unsigned char *p = NULL;
    unsigned int dmSz;

    (void)key_sz;
    (void)iv_sz;
    (void)tag_sz;
    (void)p;
    (void)i;

    if (infp == NULL || key != NULL || iv != NULL || tag != NULL){
        fprintf(stderr, "illegal parameter\n");
        return -1;
    }

    if (outfp == NULL){
        outfp = stdout;
    }

    EVP_MD_CTX *mdCtx = NULL;
    if (!(mdCtx = EVP_MD_CTX_new())) {
        printf("error\n");
    };

    EVP_MD_CTX_init(mdCtx);

    if (EVP_DigestInit(mdCtx, EVP_sha256()) != SSL_SUCCESS){
        fprintf(stderr, "EVP_DigestInit()failed\n");
        return -1;
    }

    while(1){
        if ((inl = fread(in, 1, BUFF_SIZE, infp)) < 0){
            fprintf(stderr, "fread failed\n");
            return -1;
        }
        if (EVP_DigestUpdate(mdCtx, in, inl)  != SSL_SUCCESS){
            fprintf(stderr, "EVP_DigestUpdate failed\n");
            return -1;
        }
        if (inl < BUFF_SIZE){
            break;
        }
    }

    if (EVP_DigestFinal(mdCtx, digest, &dmSz) != SSL_SUCCESS){
        fprintf(stderr, "EVP_DigestFinal failed\n");
        return -1;
    }

    if (outfp != stdout){
        if (fwrite(digest, 1, dmSz, outfp) != dmSz){
            fprintf(stderr, "fwrite failed\n");
            return 0;
        }
    } else {
        p = &digest[0];
        for (i = 0;i < dmSz;i++,p++){
            fprintf(outfp,"%02x", *p);
        }
        fprintf(outfp, "\n");
    }


    return 0;
}
