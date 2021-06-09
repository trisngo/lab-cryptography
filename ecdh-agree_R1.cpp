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
#include "include/cryptopp/nbtheory.h"
using CryptoPP::Integer;

/* Strinh input/output */
#include "include/cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::BufferedTransformation;

 /*Hex convert*/
#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

int main( int, char** ) {
     CryptoPP::OID curve = secp256r1();
    AutoSeededX917RNG<AES> rng;
    /* User A */
    ECDH < ECP >::Domain dhA(curve); // curve
    SecByteBlock privA(dhA.PrivateKeyLength()), pubA(dhA.PublicKeyLength());
    /*privA: Integer; pubA ECC::Point (04)||x||y, (03)||x*/
    dhA.GenerateKeyPair(rng, privA, pubA);
    //Integer dA(privA);
    string encode;
    encode.clear();
    StringSource(privA, privA.size(), true, 
    new HexEncoder( new StringSink(encode))
    );
    string sprivA=encode+"H";
    cout << sprivA << endl;
    Integer IprivA(sprivA.data());
    cout << "Secret key A: dA=" << IprivA << endl;

    // Public key A: QA. ssA=IprivA.QB, ssB=IprivB.QA
    encode.clear();
    StringSource(pubA, pubA.size(), true, 
    new HexEncoder( new StringSink(encode))
    );
    cout << "Public key A (hex): "<<encode << endl;
    /* Create cuver poin from public key A */
    string sQAx=encode.substr(2,encode.size()/2-1)+"H";
    string sQAy=encode.substr(1+encode.size()/2,encode.size()/2-1)+"H";
    Integer QAx(sQAx.data()), QAy(sQAy.data());
    ECP::Point QA(QAx,QAy);
    cout << "QAx="<< QA.x << endl;
    cout <<"QAy="<< QA.y << endl;
    cout << "Prime number p=" << dhA.AccessGroupParameters().GetCurve().GetField().GetModulus() << endl;
    cout << "Verify QA in ECC:" << dhA.AccessGroupParameters().GetCurve().VerifyPoint(QA) <<endl;
    
     /* User B */
    ECDH < ECP >::Domain dhB(curve);
    SecByteBlock privB(dhB.PrivateKeyLength()), pubB(dhB.PublicKeyLength());
    dhB.GenerateKeyPair(rng, privB, pubB);
    //Integer private key of BL dB(privA);
    encode.clear();
    StringSource(privB, privB.size(), true, 
    new HexEncoder( new StringSink(encode))
    );
    string sprivB=encode+"H";
    cout << sprivB << endl;
    Integer IprivB(sprivB.data());
    cout << "Secret key B: dB=" << IprivB << endl;

    // Public key B: QB
    encode.clear();
    StringSource(pubB, pubB.size(), true, 
    new HexEncoder( new StringSink(encode))
    );
    cout << "Public key B (hex): "<<encode << endl;
    /* Create cuver poin from public key A */
    string sQBx=encode.substr(2,encode.size()/2-1)+"H";
    string sQBy=encode.substr(1+encode.size()/2,encode.size()/2-1)+"H";
    Integer QBx(sQBx.data()), QBy(sQBy.data());
    ECP::Point QB(QBx,QBy);
    cout << "QAx="<< QB.x << endl;
    cout <<"QAy="<< QB.y << endl;
    cout << "Verify QB in ECC:" << dhB.AccessGroupParameters().GetCurve().VerifyPoint(QB) <<endl;
    /* Compute shared serets */
    // A compute ssA= dA.QB;
    ECP::Point ssA=dhA.AccessGroupParameters().GetCurve().Multiply(IprivA,QB);
    cout << "A shared secret ssA:" << endl;
    cout << "ssA.x=" << std::hex<<ssA.x<<endl;
    cout << "ssA.y=" << std::hex<< ssA.y<<endl;
    // B compute ssB= dB.QA;
    ECP::Point ssB=dhB.AccessGroupParameters().GetCurve().Multiply(IprivB,QA);
    cout << "B shared secret ssB:" << endl;
    cout << "ssB.x=" <<std::hex<<ssB.x<<endl;
    cout << "ssB.y=" <<std::hex<<ssB.y<<endl;
    // Verify ssA=ssB:
    cout << "ssA = ssB:" << dhA.AccessGroupParameters().GetCurve().Equal(ssA,ssB) <<endl;
    
    // Verify the kyes
    if(dhA.AgreedValueLength() != dhB.AgreedValueLength())
	throw runtime_error("Shared secret size mismatch");

    SecByteBlock sharedA(dhA.AgreedValueLength()), sharedB(dhB.AgreedValueLength());
    // Compute from this class
    const bool rtn1 = dhA.Agree(sharedA, privA, pubB); //sharedA = a(bG)
    const bool rtn2 = dhB.Agree(sharedB, privB, pubA); //sharedB = b(aG)
    // Verify
    if(!rtn1 || !rtn2)
	throw runtime_error("Failed to reach shared secret (A)");
    const bool rtn3 = sharedA.size() == sharedB.size();
    if(!rtn3)
	throw runtime_error("Failed to reach shared secret (B)");
    
    //Prerty print sharedA, sharedB
    Integer a, b;
    
    // Decode ecc point ssA 
    a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
    cout << "(A): " << std::hex << a << endl;
    
    //Decode eccpint ssB
    b.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
    cout << "(B): " << std::hex << b << endl;

    const bool rtn4 = a == b;
    if(!rtn4)
	throw runtime_error("Failed to reach shared secret (C)");

    cout << "Agreed to shared secret" << endl;

    return 0;
}