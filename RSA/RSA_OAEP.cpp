// Sample.cpp

//#include "stdafx.h"

#include "include/cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "include/cryptopp/sha.h"
using CryptoPP::SHA1;

#include "include/cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "include/cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "include/cryptopp/SecBlock.h"
using CryptoPP::SecByteBlock;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include "include/cryptopp/hex.h"//convert string to hex
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cin;
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>

int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize( rng, 3072 );

        RSA::PrivateKey privateKey( parameters );
        RSA::PublicKey publicKey( parameters );

        string plain="RSA Encryption", cipher, recovered;
        cout << "plain text: " << plain << endl;
        ////////////////////////////////////////////////
        // Encryption
        RSAES_OAEP_SHA_Encryptor e( publicKey );

        StringSource( plain, true,
            new PK_EncryptorFilter( rng, e,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
         ); // StringSource
        //pretty print cipher text
        string encoded;
        encoded.clear();
        StringSource(cipher, true,
            new HexEncoder(
                new StringSink(encoded)
            ) // HexEncoder
        ); // StringSource
        cout << "cipher text: " << encoded << endl;
        ////////////////////////////////////////////////
        ////////////////////////////////////////////////

        ////////////////////////////////////////////////
        // Decryption
        RSAES_OAEP_SHA_Decryptor d( privateKey );

        StringSource( cipher, true,
            new PK_DecryptorFilter( rng, d,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource
        cout << "recover text: " << recovered << endl;
        assert( plain == recovered );
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

	return 0;
}

