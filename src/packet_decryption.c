#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>

#include "include/common.h"

int get_buffer(unsigned char packet[]){
    FILE *fp = fopen("packet.bin", "rb");
    int ret = fread(packet, sizeof(unsigned char), 1500, fp);
    return ret;
}

struct Info{
    int payload_offset;
    int length;
    int packet_number;
    int payload_length;
};

struct Info remove_header_protection(unsigned char packet[], int packet_sz){
    int header_type;
    int pn_offset;
    unsigned long long length = 0;
    unsigned char sample[16];
    struct Info ret;
    if ((packet[0] & 0x80) != 0){
        printf("Long Header\n");
        header_type = LONG_HEADER;

        int p = 5;
        int destination_connection_id_length = packet[p++];
        p += destination_connection_id_length;
        int source_connection_id_length = packet[p++];
        p += source_connection_id_length;
        int token_length = packet[p++];
        p += token_length;

        /*
            2MSB	Length	Usable Bits	Range
            00	1	6	0-63
            01	2	14	0-16383
            10	4	30	0-1073741823
            11	8	62	0-4611686018427387903
        */

        int msb_2bit = ((packet[p]&0xc0)) >> 6;

        if (msb_2bit == 0){
            // length = 1
            length = packet[p]&0x3f;
            p++;
        } else if (msb_2bit == 1){
            length = ((packet[p]&0x3f)<<8) | (packet[p+1]);
            p+= 2;
        } else if (msb_2bit == 2){
            length = ((packet[p]&0x3f)<<24) | (packet[p+1] << 16) | (packet[p+2]<<8) | (packet[p+3]);
            p += 4;
        } else if (msb_2bit == 3){
            length = ((unsigned long long)(packet[p]&0x3f)<<56) | (unsigned long long)(packet[p+1] << 48) | (unsigned long long)(packet[p+2]<<40) | ((unsigned long long)packet[p+3]<<32) | 
                    ((packet[p+4]&0x3f)<<24) | (packet[p+5] << 16) | (packet[p+6]<<8) | (packet[p+7]);
            p += 8;
        }
        pn_offset = p;
        printf("pn_offset: %d\n", pn_offset);
        printf("length: %llu\n", length);
        for(int i = 0;i < 16;i++){
            sample[i] = packet[p + 4 + i];
        }
        for(int i = 0;i < 16;i++){
            printf("%02x ", sample[i]);
        }
        printf("\n");

/*
Long Header Packet {
Initial Packet {
    // 1byte
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 0,
  Reserved Bits (2),
  Packet Number Length (2),

  // 4byte
  Version (32),

    // 1byte
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Token Length (i),
  Token (..),
  Length (i),
  Packet Number (8..32),
  Packet Payload (8..),
}
}
*/
    } else {
        printf("Short Header\n");
        header_type = SHORT_HEADER;
    }

    // e: 1110
    // 2: 0010
    // b  1100
    int mode = ENC;

    //c300000001088394c8f03e5157080000449e00000002
    //unsigned char sample[16];
    
    int sample_length = sizeof(sample);
    printf("sample length: %d\n", sample_length);

    // server can obtained the same key from packet. 
    unsigned char key [] = {
        0x9f,0x50,0x44,0x9e,0x04,0xa0,0xe8,0x10,0x28,0x3a,0x1e,0x99,0x33,0xad,0xed,0xd2
    };

    EVP_CIPHER_CTX *evp = NULL;

    if ((evp = EVP_CIPHER_CTX_new()) == NULL){
        fprintf(stderr, "ERROR: header_protection EVP_CIPHER_CTX_NEW\n");
        return ret;
    }

    if (EVP_CipherInit(evp, EVP_aes_128_ecb(), key, NULL, mode) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: header_protection EVP_EncryptionInit\n");
        return ret;
    }

    unsigned char mask[16] = {0};
    int mask_length;
    if (EVP_CipherUpdate(evp, mask, &mask_length, sample, sample_length) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: header_protection EVP_CpiherUpdate\n");
        return ret;
    }

    unsigned char sample_answer[] = {
        0x43, 0x7b, 0x9a, 0xec, 0x36
    };

    printf("mask_length = %d\n", mask_length);
    for(int i = 0;i < 5;i++){
        printf("%02x %02x\n", sample_answer[i], mask[i]);
    }

    //header[0] ^= mask[0] & 0x0f
    // = c0
    //header[18..21] ^= mask[1..4]
    // = 7b9aec34
    //header = c000000001088394c8f03e5157080000449e7b9aec34

    printf("packet[0]: %02x, mask[0]: %02x, mask[0]&0x0f %02x\n", packet[0], mask[0], mask[0]&0x0f);
    packet[0] ^= (mask[0] & 0x0f);
    printf("packet[0]: %02x\n", packet[0]);

    int packet_number_length = (packet[0] & 0x3) + 1;
    printf("packet number length: %d\n", packet_number_length);

    unsigned long long packet_number = 0;
    for(int i = 0;i < packet_number_length;i++){
        packet_number = (packet_number << 8) + (packet[pn_offset + i] ^ mask[i+1]);
        packet[pn_offset+i] ^= mask[i+1];
        printf("packet[]: %02x, mask[i+1]: %02x\n", packet[pn_offset + i], mask[i+1]);
    }
    printf("packet_number: %d\n", packet_number);

    EVP_CIPHER_CTX_free(evp);


    ret.payload_offset = pn_offset + packet_number_length;
    ret.length = length;
    ret.packet_number = packet_number;

    ret.payload_length = length - packet_number_length;

    printf("payload_offset: %d, payload_length: %d\n", ret.payload_offset, ret.payload_length);

    return ret;
}

void packet_deprotection(unsigned char *payload, int payload_sz, unsigned char *tag, int tag_sz,
    unsigned char *original_payload, int *original_payload_sz){
    printf("tag\n");
    for(int i = 0;i < tag_sz;i++){
        printf("%02x", tag[i]);
    }
    printf("\n");

    int mode = DEC;
    // 5e is already xor-ed

    // client iv can be obtained
    unsigned char iv[] = {
        // original iv: fa044b2f42a3fd3b46fb255c
        0xfa,0x04,0x4b,0x2f,0x42,0xa3,0xfd,0x3b,0x46,0xfb,0x25,0x5e
    };
    int iv_sz = sizeof(iv);

    unsigned char key [] = {
        0x1f,0x36,0x96,0x13,0xdd,0x76,0xd5,0x46,0x77,0x30,0xef,0xcb,0xe3,0xb1,0xa2,0x2d,
    };
    int key_sz = sizeof(key);

    EVP_CIPHER_CTX *evp = NULL;

    unsigned char associated_data[] = {
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

    int payloadl;

    if ((evp = EVP_CIPHER_CTX_new()) == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new\n");
        return;
    }

    if (EVP_CipherInit(evp, EVP_aes_128_gcm(), key, iv, mode) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: EVP_EncryptInit\n");
        return;
    }

    if (EVP_CipherUpdate(evp, NULL, &payloadl, associated_data, sizeof(associated_data)) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: EVP_CipherUpdate\n");
        return;
    }

    if (EVP_CipherUpdate(evp, original_payload, &original_payload_sz, payload, payload_sz) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: EVP_CipherUpdate\n");
        return;
    }

    printf("payload         : ");
    for(int i = 0;i < 16;i++){
        printf("%02x", payload[i]);
    }
    printf("\n");
    printf("original payload: ");
    for(int i = 0;i < 16;i++){
        printf("%02x", original_payload[i]);
    }
    printf("\n");

    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_SET_TAG, tag_sz, tag) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl(DEC)\n");
    }

    if (EVP_CipherFinal(evp, original_payload, &original_payload_sz) != SSL_SUCCESS){
        fprintf(stderr, "ERROR: EVP_CipherFinal\n");
        return;
    }
    printf("original_payload_sz: %d\n", original_payload_sz);

    printf("decoded\n");
    for(int i = 0;i < 16;i++){
        printf("%02x ", original_payload[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX_free(evp);

    return;
}


int main(){
    unsigned char packet[1500];
    int packet_sz = get_buffer(packet);
    printf("packet_sz: %d\n", packet_sz);

    struct Info info = remove_header_protection(packet, packet_sz);
    printf("============================== end of remove header protextion\n");
    printf("packet size: %d\n", packet_sz);
    printf("payload_offset: %d, length: %d, packet_number: %d, payload_length: %d\n", info.payload_offset, info.length, info.packet_number, info.payload_length );

    unsigned char header_answer[] = {
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

    for(int i = 0;i < sizeof(header_answer);i++){
        if (header_answer[i] != packet[i]){
            printf("header decryption is wrong, i: %d, header_answer[i]: %02x, packet[i]: %02x\n",
                i, header_answer[i], packet[i]
            );
        }
    }
    
    printf("received packet tag\n");
    for(int i = 0;i < 16;i++){
        printf("%02x", packet[packet_sz-16+i]);
    }
    printf("\n");

    int payload_size_without_tag = info.payload_length - 16;
    // -16 decrease tag size
    unsigned char *original_payload = malloc(payload_size_without_tag);

    packet_deprotection(packet + info.payload_offset, payload_size_without_tag, 
            packet + info.payload_offset + info.payload_length - AES_BLOCK_SIZE, AES_BLOCK_SIZE,
            original_payload, &payload_size_without_tag);
    // 060040f1010000ed0303ebf8fa56f129
    printf("expected: 060040f1010000ed0303ebf8fa56f129\n");
    for(int i = 0;i < 16;i++){
        printf("%02x ", original_payload[i]);
    }
    printf("\n");


    unsigned char payload_answer[1162] = {
        0x06,0x00,0x40,0xf1,0x01,0x00,0x00,0xed,0x03,0x03,0xeb,0xf8,0xfa,0x56,0xf1,0x29,0x39,0xb9,0x58,0x4a,0x38,0x96,0x47,0x2e,0xc4,0x0b,0xb8,0x63,0xcf,0xd3,0xe8,0x68,0x04,0xfe,0x3a,0x47,0xf0,0x6a,0x2b,0x69,0x48,0x4c,0x00,0x00,0x04,0x13,0x01,0x13,0x02,0x01,0x00,0x00,0xc0,0x00,0x00,0x00,0x10,0x00,0x0e,0x00,0x00,0x0b,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x2e,0x63,0x6f,0x6d,0xff,0x01,0x00,0x01,0x00,0x00,0x0a,0x00,0x08,0x00,0x06,0x00,0x1d,0x00,0x17,0x00,0x18,0x00,0x10,0x00,0x07,0x00,0x05,0x04,0x61,0x6c,0x70,0x6e,0x00,0x05,0x00,0x05,0x01,0x00,0x00,0x00,0x00,0x00,0x33,0x00,0x26,0x00,0x24,0x00,0x1d,0x00,0x20,0x93,0x70,0xb2,0xc9,0xca,0xa4,0x7f,0xba,0xba,0xf4,0x55,0x9f,0xed,0xba,0x75,0x3d,0xe1,0x71,0xfa,0x71,0xf5,0x0f,0x1c,0xe1,0x5d,0x43,0xe9,0x94,0xec,0x74,0xd7,0x48,0x00,0x2b,0x00,0x03,0x02,0x03,0x04,0x00,0x0d,0x00,0x10,0x00,0x0e,0x04,0x03,0x05,0x03,0x06,0x03,0x02,0x03,0x08,0x04,0x08,0x05,0x08,0x06,0x00,0x2d,0x00,0x02,0x01,0x01,0x00,0x1c,0x00,0x02,0x40,0x01,0x00,0x39,0x00,0x32,0x04,0x08,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x05,0x04,0x80,0x00,0xff,0xff,0x07,0x04,0x80,0x00,0xff,0xff,0x08,0x01,0x10,0x01,0x04,0x80,0x00,0x75,0x30,0x09,0x01,0x10,0x0f,0x08,0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08,0x06,0x04,0x80,0x00,0xff,0xff
    };
    if (payload_size_without_tag != 1162){
        printf("original payload size is wrong: %d, expect: 1162\n", payload_size_without_tag);
    }
    
    for(int i = 0;i < 1162;i++){
        if (payload_answer[i] != original_payload[i]){
            printf("payload aat %d is different. payload_answer: %d, original_payload: %d\n",
                i, payload_answer[i], original_payload[i]
            );
            break;
        }
    }


    return 0;
}