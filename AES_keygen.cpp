#include "include/cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

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

#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "include/cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
#include "assert.h"

void createKey32(const char* filename)
{
	byte a[32];
	AutoSeededRandomPool prng;
	prng.GenerateBlock(a, sizeof(a));
	StringSource ss(a, sizeof(a), true , new FileSink(filename));
}

void createKey16(const char* filename)
{
	byte a[32];
	AutoSeededRandomPool prng;
	prng.GenerateBlock(a, sizeof(a));
	StringSource ss(a, sizeof(a), true , new FileSink(filename));
}

void createKey13(const char* filename)
{
	byte a[32];
	AutoSeededRandomPool prng;
	prng.GenerateBlock(a, sizeof(a));
	StringSource ss(a, sizeof(a), true , new FileSink(filename));
}

int main(int argc, char* argv[])
{	
	int choice = 0;
	cout << "Choose option below to create key you want:" << endl;
	cout << "	1.Create key 32-bytes" << endl;
	cout << "	2.Create initial vector 16-bytes" << endl;
	cout << " 	3.Create initial vector 13-bytes" << endl;
	cin >> choice;

	switch (choice)
	{
	case 1:
		createKey32("AES_key.key");
		break;
	case 2:
		createKey16("AES_iv.key");
		break;
	case 3:
		createKey13("AES_iv_13.key");
		break;
	default:
		break;
	}
	cout << "Done." << endl;
	return 0;
}