// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::wcout;
using std::wcin;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

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
using CryptoPP::Redirector; //string to bytes

#include "include/cryptopp/des.h"
using CryptoPP::DES;
using CryptoPP::DES_EDE2;
using CryptoPP::DES_EDE3;

#include "include/cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "include/cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

using CryptoPP::byte;

#include "assert.h"
#include <ctime>

/* Set _setmode()*/ 
#ifdef _WIN32
    #include <io.h>
#elif __linux__
    #include <inttypes.h>
    #include <unistd.h>
    #define __int64 int64_t
    #define _close close
    #define _read read
    #define _lseek64 lseek64
    #define _O_RDONLY O_RDONLY
    #define _open open
    #define _lseeki64 lseek64
    #define _lseek lseek
    #define stricmp strcasecmp
#endif
#include <fcntl.h>
/* Convert string*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

SecByteBlock key(DES::DEFAULT_KEYLENGTH);

SecByteBlock key_16(DES_EDE2::DEFAULT_KEYLENGTH);

SecByteBlock key_24(DES_EDE3::DEFAULT_KEYLENGTH);

byte iv[DES::BLOCKSIZE];

wstring wplain;
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
    wcout << "*** This is DES ***" << endl;
    wcout << "plain text: " << wplain << endl;
    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    wcout << "average execution times in 1000 times: " << etime << " ms" << endl << endl;
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
    wcout << "*** This is 2TDES ***" << endl;
    wcout << "plain text: " << wplain << endl;
    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    wcout << "average execution times in 1000 times: " << etime << " ms" << endl << endl;
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
    wcout << "*** This is 3TDES ***" << endl;
    wcout << "plain text: " << wplain << endl;
    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    wcout << "average execution times in 1000 times: " << etime << " ms" << endl << endl;
}

int main(int argc, char* argv[])
{
    /* Only support input and output in form wstring (wcin, wcout)*/
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

    AutoSeededRandomPool prng;

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(key_16, key_16.size());
    prng.GenerateBlock(key_24, key_24.size());
    prng.GenerateBlock(iv, sizeof(iv));
    wcout << "*** First, please type input plaintext ***" << endl;
	getline(wcin, wplain);
    plain=wstring_to_string(wplain);

	// Pretty print key
	encoded.clear();
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key 8 bits: " << string_to_wstring(encoded) << endl;

    encoded.clear();
	StringSource(key_16, key_16.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key 16 bits: " << string_to_wstring(encoded) << endl;

    encoded.clear();
	StringSource(key_24, key_24.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key 24 bits: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl << endl;
    int choice = 1;
    while (choice != 0)
    {
        wcout << "*** Please choose an option below ***" << endl;
        wcout << "   0. Quit "<< endl;
        wcout << "   1. DES modes CBC(key 8 bits) "<< endl;
        wcout << "   2. 2TDES modes CBC(key 16 bits) "<< endl;
        wcout << "   3. 3TDES modes CBC(key 24 bits) "<< endl;
        wcout << "The number of options you choose is: ";
        wcin >> choice;
        wcout << endl;
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
            wcout << "!!! You must choose a number of Algorithm option showing on the screen" << endl;
            break;
        }
    }
    wcout << "Good bye." << endl;
	return 0;
}
/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert ưstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
