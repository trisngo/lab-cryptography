//Tính toán trực tiếp private key, public key và so sánh vơi pahanf impliment của họ
// shared key
// g++ -g3 -ggdb -O0 -DDEBUG ecdh-agree.cpp -o ecdh-agree.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG ecdh-agree.cpp -o ecdh-agree.exe -lcryptopp -lpthread

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
using std::exit;

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AutoSeededX917RNG;

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDH;

#include "include/cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "include/cryptopp/oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "include/cryptopp/asn.h"
using namespace CryptoPP::ASN1;

#include "include/cryptopp/integer.h"
using CryptoPP::Integer;


int main( int, char** ) {

    CryptoPP::OID curve = secp256r1();
    AutoSeededX917RNG<AES> rng;
    /* User A */
    ECDH < ECP >::Domain dhA(curve); // curve
    SecByteBlock privA(dhA.PrivateKeyLength()), pubA(dhA.PublicKeyLength());
    /*privA: Integer; pubA ECC::Point (04)||x||y, (03)||x*/
    dhA.GenerateKeyPair(rng, privA, pubA);
    //Interger dA(privA)
    
     /* User B */
    ECDH < ECP >::Domain dhB(curve);
    SecByteBlock privB(dhB.PrivateKeyLength()), pubB(dhB.PublicKeyLength());
    dhB.GenerateKeyPair(rng, privB, pubB);

    // Verify the kyes
    if(dhA.AgreedValueLength() != dhB.AgreedValueLength())
	throw runtime_error("Shared secret size mismatch");

    SecByteBlock sharedA(dhA.AgreedValueLength()), sharedB(dhB.AgreedValueLength());

    const bool rtn1 = dhA.Agree(sharedA, privA, pubB); //sharedA = a(bG)
    const bool rtn2 = dhB.Agree(sharedB, privB, pubA); //sharedB = b(aG)
    if(!rtn1 || !rtn2)
	throw runtime_error("Failed to reach shared secret (A)");

    const bool rtn3 = sharedA.size() == sharedB.size();
    if(!rtn3)
	throw runtime_error("Failed to reach shared secret (B)");
    
    //Prerty print sharedA, sharedB
    Integer a, b;
    
    // ssA
    a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
    cout << "(A): " << std::hex << a << endl;
    
    //ssB
    b.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
    cout << "(B): " << std::hex << b << endl;

    const bool rtn4 = a == b;
    if(!rtn4)
	throw runtime_error("Failed to reach shared secret (C)");

    cout << "Agreed to shared secret" << endl;

    return 0;
}
