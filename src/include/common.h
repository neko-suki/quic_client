#ifndef CIPHER_MAIN_H
#define CIPHER_MAIN_H

#define ENC 1
#define DEC 0

#define KEY_RSA 10
#define KEY_ECC ENC
#define KEY_DH  DEC

#ifndef SSL_SUCCESS
#define SSL_SUCCESS 1
#endif
#ifndef SSL_FAILURE
#define SSL_FAILURE 0
#endif
#endif

#ifndef OPEN_MODE1
#define OPEN_MODE1 "rb"
#endif

#ifndef OPEN_MODE2
#define OPEN_MODE2 "wb"
#endif // CIPHER_MAIN_H

#ifndef SHORT_HEADER
#define SHORT_HEADER 0
#endif // SHORT_HEADER

#ifndef LONG_HEADER
#define LONG_HEADER 1
#endif // LONG_HEADER