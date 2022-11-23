#include <stdio.h>
#include <string.h>

#include "include/common.h"
#include "include/algo_main.h"

static int hex2int(int hex) {
    if (hex >= '0' && hex <= '9')
        return hex - '0';
    else if (hex >= 'a' && hex <= 'f')
        return hex - 'a' + 10;
    else if (hex >= 'A' && hex <= 'F')
        return hex - 'A' + 10;
    else return -1;
}

static unsigned char *hex2bin(char *hex, int *sz)
{
    int n, i;
    unsigned char *bin, *b;    

    *sz = (strlen(hex)+1)/2;
    if ((bin = (unsigned char *)malloc(*sz)) == NULL)
        return NULL;
    memset(bin, 0, *sz);
    b = bin;

    for( ; ; b++) {
        for(i=0; i<2; i++, hex++) {
            if(*hex == '\0')return bin;
            if((n = hex2int(*hex)) >= 0)
                *b = *b * 0x10 + n;
            else return NULL;
        }
    }
    return bin;
}


int main(int argc, char **argv)
{
    FILE *fp1  = NULL;
    FILE *fp2 = NULL;
    int mode = -1;
    unsigned char *key = NULL;
    unsigned char *iv  = NULL;
    unsigned char *tag = NULL;
    unsigned char *v = NULL;
    int key_sz = 0;
    int iv_sz  = 0;
    int tag_sz = 0;
    int ret = 0;
    int sz;
    int i;

    for(i = 1; i < argc; i++) {
        if(argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'e': mode = ENC; break;
                case 'd': mode = DEC; break;
                case 'r': mode = KEY_RSA; break;

                case 'i':
                case 'k' :
                case 't':
                    v = hex2bin(argv[i+1], &sz);
                    break;

                default:
                    fprintf(stderr, "ERROR: Invalid option (-%c)\n", argv[i][1]);
                    goto cleanup;
            }
            if(v != NULL) {
                switch (argv[i][1]) {
                    case 'k' : key = v; key_sz = sz; i++; break;
                    case 'i' : iv  = v; iv_sz  = sz; i++; break;
                    case 't' : tag = v; tag_sz = sz; i++; break;
                }
            } else {
                switch (argv[i][1]) {
                    case 'e':
                    case 'd':
                    case 'r':
                        break;
                    default:
                        fprintf(stderr, "ERROR: Invalid option (-%c)\n", argv[i][1]);
                    goto cleanup;
                }
            }
        }
        else break;
        v = NULL;
    }
    
    if (i < argc)
    {
        if ((fp1 = fopen(argv[i], OPEN_MODE1)) == NULL)
        {
            fprintf(stderr, "ERROR: Open input file (%s)\n", argv[i]);
            goto cleanup;
        }
    }
    i++;
    if (i <argc)
    {
        if ((fp2 = fopen(argv[i], OPEN_MODE2)) == NULL)
        {
            fprintf(stderr, "ERROR: Open output file (%s)\n", argv[i]);
            goto cleanup;
        }
    }

    ret = algo_main(mode, fp1, fp2, key, key_sz, iv, iv_sz, tag, tag_sz);

cleanup:
    if(fp1 != NULL)
        fclose(fp1);
    if(fp2 != NULL && fp2 != stdout)
        fclose(fp2);
    if (key != NULL) free(key);
    if (iv  != NULL) free(iv);
    if (tag != NULL) free(tag);
    return ret;
}