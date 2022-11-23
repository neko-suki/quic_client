#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>

#include "include/common.h"

#define CIPHER EVP_aes_128_ecb()

int algo_main(){
    // e: 1110
    // 2: 0010
    // b  1100
    int mode = ENC;
    unsigned char header[] = {
        0xc3,0x00,
        0x00,0x00,
        0x01,0x08,
        0x83,0x94,
        0xc8,0xf0,
        0x3e,0x51,
        0x57,0x08,
        0x00,0x00,
        0x44,0x9e,
        0x00,0x00,
        0x00,0x02
    };
//c300000001088394c8f03e5157080000449e00000002

    unsigned char sample[] = {
        0xd1,0xb1,
        0xc9,0x8d,
        0xd7,0x68,
        0x9f,0xb8,
        0xec,0x11,
        0xd2,0x42,
        0xb1,0x23,
        0xdc,0x9b
    };
    int in_length = sizeof(sample);

    unsigned char key [] = {
        0x9f,0x50,0x44,0x9e,0x04,0xa0,0xe8,0x10,0x28,0x3a,0x1e,0x99,0x33,0xad,0xed,0xd2
    };

    EVP_CIPHER_CTX *evp = NULL;

    if ((evp = EVP_CIPHER_CTX_new()) == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_NEW\n");
        return 0;
    }

    if (EVP_CipherInit(evp, CIPHER, key, NULL, mode) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: EVP_EncryptionInit\n");
        return 0;
    }

    unsigned char out[16] = {0};
    int out_length;
    if (EVP_CipherUpdate(evp, out, &out_length, sample, in_length) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: EVP_CpiherUpdate\n");
        return 0;
    }

    unsigned char sample_answer[] = {
        0x43, 0x7b, 0x9a, 0xec, 0x36
    };

    printf("out_length = %d\n", out_length);
    for(int i = 0;i < 5;i++){
        printf("%02x %02x\n", sample_answer[i], out[i]);
    }


    //if (EVP_CipherFinal(evp, out, &out_length) != SSL_SUCCESS){
    //    fprintf(stderr, "ERROR:EVP_CipherFInal\n");
    //    return 0;
    //}


    //header[0] ^= mask[0] & 0x0f
    // = c0
    //header[18..21] ^= mask[1..4]
    // = 7b9aec34
    //header = c000000001088394c8f03e5157080000449e7b9aec34

    printf("check 18 .. 21\n");
    for(int i = 18;i <= 21;i++){
        printf("%02x %02x, %02x\n", header[i], out[i-18], header[i] ^out[i-18]);
    }


    header[0] ^= out[0] & 0x0f;
    for(int i = 18, mask=1;i <=21 && mask <= 4;i++, mask++){
        header[i] ^= out[mask];
    }


    printf("header_length = %d\n", sizeof(header));
    for(int i = 0;i < sizeof(header);i++){
        printf("%02x", header[i]);
    }
    printf("\n");

    unsigned char header_answer[] = {
        0xc0,0x00,0x00,0x00,0x01,0x08,0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08,0x00,0x00,0x44,0x9e,0x7b,0x9a,0xec,0x34,
    };
    for(int i = 0;i < sizeof(header_answer);i++){
        printf("%02x", header_answer[i]);
    }
    printf("\n");

    for(int i = 0;i < sizeof(header_answer);i++){
        if (header_answer[i] != header[i]){
            printf("%d th point is wrong. answer: %02x outptu: %02x\n", i, header[i], header_answer[i]);
            return 0;
        }
    }
    printf("correct\n");

    return 0;
}

int main(){
    algo_main();
    return 0;
}