#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

#include "include/algo_main.h"

#define BUFF_SIZE 16

int algo_main(int mode, FILE *infp, FILE *outfp,
    unsigned char *key, int key_sz,
    unsigned char *iv, int iv_sz,
    unsigned char *tag, int tag_sz
){
    HMAC_CTX* hctx = NULL;
    char in[BUFF_SIZE];
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int len;
    int inl;
    int i;
    unsigned char * p;
    const EVP_MD *md = NULL;

    (void)iv_sz;
    (void)tag_sz;
    (void)i;
    (void)p;

    if (infp == NULL || key == NULL || key_sz == 0 || iv != NULL || tag != NULL){
        fprintf(stderr, "illegal parameter.\n");
        return 0;
    }

    if (outfp == NULL){
        outfp = stdout;
    }
    printf("key: %02x %02x size = %d\n", key[0], key[1], key_sz);
    md = EVP_get_digestbyname("SHA1");
    if (md == NULL){
        fprintf(stderr, "EVP_get_digestbyname failed\n");
        return 0;
    }

    if ((hctx = HMAC_CTX_new()) == NULL){
        fprintf(stderr, "HMAC_CTX_new failed.\n");
        return 0;
    }

    if (HMAC_Init_ex(hctx, key, key_sz, md, NULL) != SSL_SUCCESS){
        fprintf(stderr, "HMAC_Init failed.\n");
    }

    while (1){
        if ((inl = fread(in, 1, BUFF_SIZE, infp)) < 0){
            fprintf(stderr, "fread failed.\n");
            return 0;
        }
        if (HMAC_Update(hctx, (const unsigned char*)in, inl) != SSL_SUCCESS){
            fprintf(stderr, "HMAC_Update failed.\n");
            return 0;
        }
        if (inl < BUFF_SIZE){
            break;
        }
    }

    if (HMAC_Final(hctx, hmac, &len) != SSL_SUCCESS){
        fprintf(stderr, "HMAC_Final failed.\n");
    }
    if (outfp != stdout){
        if (fwrite(hmac, 1, len, outfp) != len){
            fprintf(stderr, "fwrite failed.\n");
            return 0;
        }
    } else {
        p = &hmac[0];
        for(i = 0;i < len;i++, p++){
            fprintf(outfp, "%02x", *p);
        }
        fprintf(outfp, "\n");
    }


    return 0;
}