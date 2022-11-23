#ifndef ALGO_MAIN_H
#define ALGO_MAIN_H

#include "common.h"

int algo_main(int mode, FILE *infp, FILE *outfp,
        unsigned char *key, int key_sz,
        unsigned char *iv, int iv_sz,
        unsigned char *tag, int tag_sz);
#endif // ALGO_MAIN_H