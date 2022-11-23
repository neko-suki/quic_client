#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>

#include "include/common.h"

#define CIPHER EVP_aes_128_gcm()

#define BUFF_SIZE 512

#define CUSTOM

static int msg_write(int mode, unsigned char *buf, int sz, FILE *outfp){
    int i;
    unsigned char *p = NULL;

    (void)i;
    (void)p;

    if (outfp != stdout){
        if (fwrite(buf, 1, sz, outfp) != sz){
            fprintf(stderr, "fwrite, failed.\n");
            return -1;
        } else {
            return sz;
        }
    } else {
        p = &buf[0];
        for(i = 0;i < sz;i++, p++){
            if (mode == ENC){
                fprintf(outfp, "%02x", *p);
            } else {
                fprintf(outfp, "%c", *p);
            }
        }
        fprintf(outfp, "\n");
    }
}

int algo_main(int mode, FILE *infp, FILE *outfp,
    unsigned char *key, int key_sz,
    unsigned char *iv, int iv_sz,
    unsigned char *tagIn, int tag_sz
){
    EVP_CIPHER_CTX *evp = NULL;
#ifdef ORIGINAL
    unsigned char in[BUFF_SIZE];
#endif
    unsigned char out[BUFF_SIZE*2 + AES_BLOCK_SIZE];
    unsigned char tagOut[BUFF_SIZE];
    int inl, outl;
    int ret = SSL_FAILURE;
    int i;
    unsigned char *p = NULL;

    (void)i;
    (void)p;

    if (mode < 0){
        mode = ENC;
    }

#ifdef CUSTOM
    unsigned char *in;
    int in_length;
    printf("a\n");
    if (mode == ENC){
        char tmp[1162] = {0x06,0x00,0x40,0xf1,0x01,0x00,0x00,0xed,0x03,0x03,0xeb,0xf8,0xfa,0x56,0xf1,0x29,0x39,0xb9,0x58,0x4a,0x38,0x96,0x47,0x2e,0xc4,0x0b,0xb8,0x63,0xcf,0xd3,0xe8,0x68,0x04,0xfe,0x3a,0x47,0xf0,0x6a,0x2b,0x69,0x48,0x4c,0x00,0x00,0x04,0x13,0x01,0x13,0x02,0x01,0x00,0x00,0xc0,0x00,0x00,0x00,0x10,0x00,0x0e,0x00,0x00,0x0b,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x2e,0x63,0x6f,0x6d,0xff,0x01,0x00,0x01,0x00,0x00,0x0a,0x00,0x08,0x00,0x06,0x00,0x1d,0x00,0x17,0x00,0x18,0x00,0x10,0x00,0x07,0x00,0x05,0x04,0x61,0x6c,0x70,0x6e,0x00,0x05,0x00,0x05,0x01,0x00,0x00,0x00,0x00,0x00,0x33,0x00,0x26,0x00,0x24,0x00,0x1d,0x00,0x20,0x93,0x70,0xb2,0xc9,0xca,0xa4,0x7f,0xba,0xba,0xf4,0x55,0x9f,0xed,0xba,0x75,0x3d,0xe1,0x71,0xfa,0x71,0xf5,0x0f,0x1c,0xe1,0x5d,0x43,0xe9,0x94,0xec,0x74,0xd7,0x48,0x00,0x2b,0x00,0x03,0x02,0x03,0x04,0x00,0x0d,0x00,0x10,0x00,0x0e,0x04,0x03,0x05,0x03,0x06,0x03,0x02,0x03,0x08,0x04,0x08,0x05,0x08,0x06,0x00,0x2d,0x00,0x02,0x01,0x01,0x00,0x1c,0x00,0x02,0x40,0x01,0x00,0x39,0x00,0x32,0x04,0x08,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x05,0x04,0x80,0x00,0xff,0xff,0x07,0x04,0x80,0x00,0xff,0xff,0x08,0x01,0x10,0x01,0x04,0x80,0x00,0x75,0x30,0x09,0x01,0x10,0x0f,0x08,0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08,0x06,0x04,0x80,0x00,0xff,0xff};
        int cnt = 0;
        in = malloc(sizeof(char) * sizeof(tmp));
        memcpy(in, tmp, sizeof(tmp));
        printf("sizeof(tmp): %d\n", sizeof(tmp));
        in_length = sizeof(tmp);
    } else {
        in = malloc(sizeof(char) * BUFF_SIZE);
    printf("c\n");

    }
    
#endif


    if (mode == ENC && tagIn != NULL){
        fprintf(stderr, "ERROR: Tag Option with Enc mode");
        return ret;
    } else {
        tag_sz = AES_BLOCK_SIZE;
    }

    if (mode == DEC && tagIn == NULL){
        fprintf(stderr, "ERROR: No Tag Option with Dec mode\n");
        return ret;
    }

    if (key == NULL || iv == NULL){
        fprintf(stderr, "ERROR: Missing Option key or iv\n");
        return ret;
    }

printf("key_sz: %d, iv_sz: %d\n", key_sz, iv_sz);
/*
    if (key_sz != 128/8){
        fprintf(stderr, "ERROR: Key size = %d\n", key_sz);
        return ret;
    }
    if (iv_sz != 96/8){
        printf("96/8 = %d\n", 96/8);
        printf("%s\n", iv);
        fprintf(stderr, "ERROR: IV size = %d\n", iv_sz);
        return 0;
    }
*/

    if (outfp == NULL){
        outfp = stdout;
    }

    if ((evp = EVP_CIPHER_CTX_new()) == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new\n");
        return 0;
    }

    if (EVP_CipherInit(evp, CIPHER, key, iv, mode) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: EVP_EncryptInit\n");
        return 0;
    }

    while(1) {
#ifdef ORIGINAL
        if ((inl = fread(in, 1, BUFF_SIZE, infp)) < 0) {
            fprintf(stderr, "ERROR: fread\n");
            return 0;
        }
#endif

#ifdef CUSTOM
        if (mode == ENC){
            inl = in_length;
            printf("inl: %d\n", in_length);
        } else if ((inl = fread(in, 1, BUFF_SIZE, infp)) < 0) {
            fprintf(stderr, "ERROR: fread\n");
            return 0;
        }
#endif
        printf("inl: %d\n", inl);

        if (EVP_CipherUpdate(evp, out, &outl, in, inl) != SSL_SUCCESS){
            fprintf(stderr, "ERROR: EVP_CipherUpdate\n");
            return 0;
        }
        if (msg_write(mode, out, outl, outfp) != outl){
            return 0;
        }
#ifdef CUSTOM
        if (mode == ENC){
            break;
        }
#endif
        if (inl < BUFF_SIZE){
            break;
        }
    }

    if (mode == DEC){
        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_SET_TAG, tag_sz, tagIn) != SSL_SUCCESS){
            fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl(DEC)\n");
            return 0;
        }
    }

    if (EVP_CipherFinal(evp, out, &outl) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: EVP_CipherFinal\n");
        return 0;
    }

    if (mode == ENC){
        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_GET_TAG, tag_sz, tagOut) != SSL_SUCCESS){
            fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl(ENC)\n");
            return 0;            
        }
        for(i = 0;i < tag_sz;i++){
            printf("%02x", tagOut[i]);
        }
        putchar('\n');
    }
    msg_write(mode, out, outl, outfp);

    EVP_CIPHER_CTX_free(evp);
    return 0;
}