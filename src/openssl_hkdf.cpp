#include <iostream>

#include <string>
#include <vector>

#include <botan-2/botan/hkdf.h>
#include <botan-2/botan/hmac.h>

std::vector<uint8_t> derive_key(size_t key_length, std::vector<uint8_t> &secret_in, std::string & label_string){

//    Botan::HKDF hkdf(Botan::HMAC);
    std::unique_ptr<Botan::KDF> hkdf(Botan::KDF::create(std::string("HKDF-Expand(HMAC(SHA-256))")));

    Botan::secure_vector<uint8_t> secret(secret_in.begin(), secret_in.end());

    /*
       struct {
           uint16 length = Length;
           opaque label<7..255> = "tls13 " + Label;
           opaque context<0..255> = Context;
       } HkdfLabel;
    */

    std::string label = {
        // 32
        (key_length&0xff00) >> 8, (key_length&0xff),
        // length of client in
        0x0f,
        // "tls13 client in"
        // 0
    };
    label += label_string;
    label.push_back(0);

    std::cout <<"c" << std::endl;    
    auto key = hkdf->derive_key(
        32,
        secret.data(),
        secret.size(),
        "",
        label
    );
 
    std::vector<uint8_t> ret(key.begin(), key.end());
    return ret;
}

int main(){
    size_t key_length = 32;

//    Botan::HKDF hkdf(Botan::HMAC);
    std::cout <<"a" << std::endl;
    std::unique_ptr<Botan::KDF> hkdf(Botan::KDF::create(std::string("HKDF-Expand(HMAC(SHA-256))")));
    std::cout <<"b"<<std::endl;

    std::vector<uint8_t> secret_in = {
        0x7d,0xb5,0xdf,0x06,0xe7,0xa6,0x9e,0x43,0x24,0x96,
        0xad,0xed,0xb0,0x08,0x51,0x92,0x35,0x95,0x22,0x15,
        0x96,0xae,0x2a,0xe9,0xfb,0x81,0x15,0xc1,0xe9,0xed,
        0x0a,0x44       
    };
    std::string label_string = "tls13 client in";
 
    std::vector<uint8_t> key = derive_key(key_length, secret_in, label_string);
    std::cout<<"key" << std::endl;
    for(int i = 0;i < key.size();i++){
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;
}