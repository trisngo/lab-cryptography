// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cin;
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

#include "include/cryptopp/des.h"
using CryptoPP::DES;
using CryptoPP::DES_EDE2;
using CryptoPP::DES_EDE3;

#include "include/cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "include/cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

using CryptoPP::byte;

SecByteBlock key(DES::DEFAULT_KEYLENGTH);

SecByteBlock key_16(DES_EDE2::DEFAULT_KEYLENGTH);

SecByteBlock key_24(DES_EDE3::DEFAULT_KEYLENGTH);

byte iv[DES::BLOCKSIZE];

string plain, cipher, encoded, recovered;

void des()
{
    int start_s = clock();
    int i = 0;
    while (i<=1000)
    {
        cipher.clear();
        recovered.clear();
        try
        {
            CBC_Mode< DES >::Encryption e;
            e.SetKeyWithIV(key, key.size(), iv);

            // The StreamTransformationFilter adds padding
            //  as required. ECB and CBC Mode must be padded
            //  to the block size of the cipher.
            StringSource(plain, true, 
                new StreamTransformationFilter(e,
                    new StringSink(cipher)
                ) // StreamTransformationFilter      
            ); // StringSource
        }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            return;
        }

        try
        {
            CBC_Mode< DES >::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv);

            // The StreamTransformationFilter removes
            //  padding as required.
            StringSource s(cipher, true, 
                new StreamTransformationFilter(d,
                    new StringSink(recovered)
                ) // StreamTransformationFilter
            ); // StringSource
        }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            return;
        }
        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    cout << "*** This is DES ***" << endl;
    cout << "plain text: " << plain << endl;
    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    cout << "cipher text: " << encoded << endl;
    cout << "recovered text: " << recovered << endl;
    cout << "average execution times in 1000 times: " << etime << " ms" << endl << endl;
}

void dou_tdes()
{
    int start_s = clock();
    int i = 0;
    while (i<=1000)
    {
        cipher.clear();
        recovered.clear();
        try
	    {
		CBC_Mode< DES_EDE2 >::Encryption e;
		e.SetKeyWithIV(key_16, key_16.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	    }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            return;
        }

        try
        {
            CBC_Mode< DES_EDE2 >::Decryption d;
            d.SetKeyWithIV(key_16, key_16.size(), iv);

            // The StreamTransformationFilter removes
            //  padding as required.
            StringSource s(cipher, true, 
                new StreamTransformationFilter(d,
                    new StringSink(recovered)
                ) // StreamTransformationFilter
            ); // StringSource
        }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            return;
        }

        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    cout << "*** This is 2TDES ***" << endl;
    cout << "plain text: " << plain << endl;
    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    cout << "cipher text: " << encoded << endl;
    cout << "recovered text: " << recovered << endl;
    cout << "average execution times in 1000 times: " << etime << " ms" << endl << endl;
}

void tri_tdes()
{
    int start_s = clock();
    int i = 0;
    while (i<=1000)
    {
        cipher.clear();
        recovered.clear();
        try
        {

            CBC_Mode< DES_EDE3 >::Encryption e;
            e.SetKeyWithIV(key_24, key_24.size(), iv);

            // The StreamTransformationFilter adds padding
            //  as required. ECB and CBC Mode must be padded
            //  to the block size of the cipher.
            StringSource(plain, true, 
                new StreamTransformationFilter(e,
                    new StringSink(cipher)
                ) // StreamTransformationFilter      
            ); // StringSource
        }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            return;
        }

        try
        {
            CBC_Mode< DES_EDE3 >::Decryption d;
            d.SetKeyWithIV(key_24, key_24.size(), iv);

            // The StreamTransformationFilter removes
            //  padding as required.
            StringSource s(cipher, true, 
                new StreamTransformationFilter(d,
                    new StringSink(recovered)
                ) // StreamTransformationFilter
            ); // StringSource
        }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            return;
        }
        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    cout << "*** This is 3TDES ***" << endl;
    cout << "plain text: " << plain << endl;
    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    cout << "cipher text: " << encoded << endl;
    cout << "recovered text: " << recovered << endl;
    cout << "average execution times in 1000 times: " << etime << " ms" << endl << endl;
}

int main(int argc, char* argv[])
{
    
    AutoSeededRandomPool prng;

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, sizeof(iv));
    cout << "*** First, please type input plaintext ***" << endl;
	getline(cin, plain);//co the ddoi thanh cai khac

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key 8 bits: " << encoded << endl;

    encoded.clear();
	StringSource(key_16, sizeof(key_16), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key 16 bits: " << encoded << endl;

    encoded.clear();
	StringSource(key_24, sizeof(key_24), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key 24 bits: " << encoded << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl << endl;
    int choice = 1;
    string pause;
    while (choice != 0)
    {
        cout << "*** Please choose an option below ***" << endl;
        cout << "   0. Quit "<< endl;
        cout << "   1. DES modes CBC(key 8 bits) "<< endl;
        cout << "   2. 2TDES modes CBC(key 16 bits) "<< endl;
        cout << "   3. 3TDES modes CBC(key 24 bits) "<< endl;
        cout << "The number of options you choose is: ";
        cin >> choice;
        cout << endl;
        switch (choice)
        {
        case 0:
            break;
        case 1:
            des();
            break;
        case 2:
            dou_tdes();
            break;
        case 3:
            tri_tdes();
            break;
        default:
            cout << "!!! You must choose a number of Algorithm option showing on the screen" << endl;
            break;
        }
    }
    cout << "Good bye." << endl;
    cin >> pause;

	return 0;
}

