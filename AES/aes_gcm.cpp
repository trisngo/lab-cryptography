// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cin;
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::byte;

#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "include/cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/gcm.h"
using CryptoPP::GCM;

#include "include/cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	SecByteBlock iv(AES::BLOCKSIZE);
	prng.GenerateBlock(iv, iv.size());

	// cout << "key length: " << AES::DEFAULT_KEYLENGTH << endl;
	// cout << "key length (min): " << AES::MIN_KEYLENGTH << endl;
	// cout << "key length (max): " << AES::MAX_KEYLENGTH << endl;
	// cout << "block size: " << AES::BLOCKSIZE << endl;

	string plain;
	cout << "input plaintext: ";
	cin >> plain;
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, iv.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		GCM< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv, iv.size());

		// The StreamTransformationFilter adds padding
		//  as required. GCM and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new AuthenticatedEncryptionFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		GCM< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv, iv.size());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new AuthenticatedDecryptionFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}

