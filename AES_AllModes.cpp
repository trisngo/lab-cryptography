// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

//khong chay song song nen performance khac hoan toan
//luc nhan input thi can decode unicode de nhan tieng Viet
//luc decrypt xuat ra thi can encode unicode
//se co 1 doan fix key la minh go chuoi key, phai coi dung chuan chuoi byte cua key
//mot blockcode de tinh thoi gian bao gon create key, block, encrypt, doi ra dang de doc

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::wcin;//dung gi call len de giam dung luong cung nhu bugs
using std::wcout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::byte;
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "include/cryptopp/hex.h"//convert string to hex
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "include/cryptopp/filters.h"//nhan input tung string vao dong thanh dang buffer, co the them ArraySink, ArraySource
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
//filter for authenticate
using CryptoPP::Redirector; //string to bytes
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/modes.h"
#include "include/cryptopp/ccm.h"
using CryptoPP::CCM;

using CryptoPP::CBC_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::CFB_Mode;

#include "include/cryptopp/gcm.h"
using CryptoPP::GCM;

#include "include/cryptopp/xts.h"
using CryptoPP::XTS_Mode;

//thu vien dung de them cac thong bao chan loi
#include "assert.h"
#include <ctime>

#include "include/cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

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

wstring wplain;
string plain, cipher, encoded, recovered;
byte key[32];
byte iv[AES::BLOCKSIZE];
byte iv_ccm[13];

void aesCBC()
{
    int start_s = clock();
    int i = 0;
    while (i<1000)
    {
        cipher.clear();
        recovered.clear();
        try
        {
            CBC_Mode< AES >::Encryption e;
            e.SetKeyWithIV(key, sizeof(key), iv);

            // The StreamTransformationFilter removes
            //  padding as required.
            StringSource s(plain, true, 
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
            CBC_Mode< AES >::Decryption d;
            d.SetKeyWithIV(key, sizeof(key), iv);

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
    wcout << "*** This is AES CBC mode ***" << endl;
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

void aesOFB()
{
	int start_s = clock();
    int i = 0;
    while (i<1000)
    {
        cipher.clear();
        recovered.clear();
        try
        {
            OFB_Mode< AES >::Encryption e;//goi ham encryp ofb o aes, dat ham nay la d
            e.SetKeyWithIV(key, sizeof(key), iv);

            // OFB mode must not use padding. Specifying
            //  a scheme will result in an exception
            StringSource(plain, true, 
                new StreamTransformationFilter(e, //e la ham ma
                    new StringSink(cipher) //van nho trong buffer, va cipher o dang hex
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
            OFB_Mode< AES >::Decryption d;
            d.SetKeyWithIV(key, sizeof(key), iv);

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
    wcout << "*** This is AES OFB mode ***" << endl;
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

void aesCTR()
{
    int start_s = clock();
    int i = 0;
    while (i<1000)
    {
        cipher.clear();
        recovered.clear();

        try
        {
            CTR_Mode< AES >::Encryption e;
            e.SetKeyWithIV(key, sizeof(key), iv);

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
            CTR_Mode< AES >::Decryption d;
            d.SetKeyWithIV(key, sizeof(key), iv);

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
    wcout << "*** This is AES CTR mode ***" << endl;
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

void aesECB()
{
    int start_s = clock();
    int i = 0;
    while (i<1000)
    {
        cipher.clear();
        recovered.clear();

        try
        {
            ECB_Mode< AES >::Encryption e;
            e.SetKey(key, sizeof(key));

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
            ECB_Mode< AES >::Decryption d;
            d.SetKey(key, sizeof(key));

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
    wcout << "*** This is AES ECB mode ***" << endl;
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

void aesCFB()
{
    int start_s = clock();
    int i = 0;
    while (i<1000)
    {
        cipher.clear();
        recovered.clear();

        try
        {
            CFB_Mode< AES >::Encryption e;
            e.SetKeyWithIV(key, sizeof(key), iv);

            // CFB mode must not use padding. Specifying
            //  a scheme will result in an exception
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
            CFB_Mode< AES >::Decryption d;
            d.SetKeyWithIV(key, sizeof(key), iv);

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
    wcout << "*** This is AES CFB mode ***" << endl;
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

void aesGCM()
{
int start_s = clock();
    int i = 0;
    while (i<1000)
    {
        cipher.clear();
        recovered.clear();

        try
        {

            GCM< AES >::Encryption e;
            e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

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
            return;
        }

        try
        {
            GCM< AES >::Decryption d;
            d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

            // The StreamTransformationFilter removes
            //  padding as required.
            StringSource s(cipher, true, 
                new AuthenticatedDecryptionFilter(d,
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
    wcout << "*** This is AES GCM mode ***" << endl;
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

void aesXTS()
{
    int start_s = clock();
    int i = 0;
    while (i<1000)
    {
        cipher.clear();
        recovered.clear();

        try
        {
            XTS_Mode< AES >::Encryption enc;
            enc.SetKeyWithIV( key, sizeof(key), iv );

            // The StreamTransformationFilter adds padding
            //  as requiredec. ECB and XTS Mode must be padded
            //  to the block size of the cipher.
            StringSource ss( plain, true, 
                new StreamTransformationFilter( enc,
                    new StringSink( cipher ),
                    StreamTransformationFilter::NO_PADDING
                ) // StreamTransformationFilter      
            ); // StringSource
        }
        catch( const CryptoPP::Exception& ex )
        {
            std::cerr << ex.what() << std::endl;
            return;
        }

        try
        {
            XTS_Mode< AES >::Decryption dec;
            dec.SetKeyWithIV( key, sizeof(key), iv );

            // The StreamTransformationFilter removes
            //  padding as requiredec.
            StringSource ss( cipher, true, 
                new StreamTransformationFilter( dec,
                    new StringSink( recovered ),
                    StreamTransformationFilter::NO_PADDING
                ) // StreamTransformationFilter
            ); // StringSource        
        }
        catch( const CryptoPP::Exception& ex )
        {
            std::cerr << ex.what() << std::endl;
            return;
        }
        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    wcout << "*** This is AES XTS mode ***" << endl;
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

void aesCCM()
{

    // { 4, 6, 8, 10, 12, 14, 16 }
    const int TAG_SIZE = 8;

    int start_s = clock();
    int i = 0;
    while (i<1000)
    {
        cipher.clear();
        recovered.clear();

        try
        {
            CCM< AES, TAG_SIZE >::Encryption e;
            e.SetKeyWithIV( key, sizeof(key), iv_ccm, sizeof(iv_ccm) );
            e.SpecifyDataLengths( 0, plain.size(), 0 );

            StringSource( plain, true,
                new AuthenticatedEncryptionFilter( e,
                    new StringSink( cipher )
                ) // AuthenticatedEncryptionFilter
            ); // StringSource
        }
        catch( CryptoPP::InvalidArgument& e )
        {
            cerr << "Caught InvalidArgument..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            return;
        }
        catch( CryptoPP::Exception& e )
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            return;
        }

        try
        {
            CCM< AES, TAG_SIZE >::Decryption d;
            d.SetKeyWithIV( key, sizeof(key), iv_ccm, sizeof(iv_ccm) );
            d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );

            AuthenticatedDecryptionFilter df( d,
                new StringSink( recovered )
            ); // AuthenticatedDecryptionFilter

            StringSource( cipher, true,
                new Redirector( df /*, PASS_EVERYTHING */ )
            ); // StringSource

        }
        catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
        {
            cerr << "Caught HashVerificationFailed..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            return;
        }
        catch( CryptoPP::InvalidArgument& e )
        {
            cerr << "Caught InvalidArgument..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            return;
        }
        catch( CryptoPP::Exception& e )
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            return;
        }
        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    wcout << "*** This is AES CCM mode ***" << endl;
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

	wcout << "*** First, please type input plaintext ***" << endl;
	getline(wcin,wplain);
    plain=wstring_to_string(wplain);
	
    int choice = 1;
    wcout << "*** Please choose an option below ***" << endl;
    wcout << "   0. Quit "<< endl;
    wcout << "   1. AES modes CBC "<< endl;
    wcout << "   2. AES modes OFB "<< endl;
    wcout << "   3. AES modes CTR "<< endl;
    wcout << "   4. AES modes ECB "<< endl;
    wcout << "   5. AES modes CFB "<< endl;
    wcout << "   6. AES modes GCM "<< endl;
    wcout << "   7. AES modes XTS "<< endl;
    wcout << "   8. AES modes CCM "<< endl;
    wcout << "   9. DES modes CBC "<< endl;
    wcout << "   10. 2TDES modes CBC "<< endl;
    wcout << "   11. 3TDES modes CBC "<< endl;
    wcout << "The option number you choose is: ";
    wcin >> choice;
    wcin.ignore();
    wcout << endl;

    AutoSeededRandomPool prng;//tao chuoi bit random, dau ra la byte

    prng.GenerateBlock(key, sizeof(key));
    encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << sizeof(key) <<"-bit key: " << string_to_wstring(encoded) << endl;
    if(choice == 8)
    {
        wcout << "Maximum Initialization Vector for CCM mode is 13bit" << endl;
        prng.GenerateBlock(iv_ccm, 13);
        // Pretty print iv
        encoded.clear();
        StringSource(iv_ccm, sizeof(iv_ccm), true,
            new HexEncoder(
                new StringSink(encoded)
            ) // HexEncoder
        ); // StringSource
        wcout << sizeof(iv_ccm) <<"-bit iv: " << string_to_wstring(encoded) << endl;
    }
    else{
	    prng.GenerateBlock(iv, sizeof(iv));
        // Pretty print iv
        encoded.clear();
        StringSource(iv, sizeof(iv), true,
            new HexEncoder(
                new StringSink(encoded)
            ) // HexEncoder
        ); // StringSource
        wcout << sizeof(iv) <<"-bit iv: " << string_to_wstring(encoded) << endl;
    }
    switch (choice)
    {
    case 0:
        break;
    case 1:
        aesCBC();
        break;
    case 2:
        aesOFB();
        break;
    case 3:
        aesCTR();
        break;
    case 4:
        aesECB();
        break;
    case 5:
        aesCFB();
        break;
    case 6:
        aesGCM();
        break;
    case 7:
        aesXTS();
        break;
    case 8:
        aesCCM();
        break;
    default:
        wcout << "!!! You must choose a number of Algorithm option showing on the screen" << endl;
        break;
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