#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::wcin;
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

#include "include/cryptopp/filters.h"//input string to buffer
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
//filter for authenticate
using CryptoPP::Redirector; //string to bytes
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/des.h"
using CryptoPP::DES;
using CryptoPP::DES_EDE2;
using CryptoPP::DES_EDE3;

#include "include/cryptopp/modes.h"

using CryptoPP::CBC_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::CFB_Mode;

#include "include/cryptopp/ccm.h"
using CryptoPP::CCM;

#include "include/cryptopp/gcm.h"
using CryptoPP::GCM;

#include "include/cryptopp/xts.h"
using CryptoPP::XTS_Mode;

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
#include <sstream>
using std::ostringstream;

/* Functions def*/
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);
wstring integer_to_wstring(const CryptoPP::Integer& t);
void aesCBC();
void aesOFB();
void aesCTR();
void aesECB();
void aesCFB();
void aesGCM();
void aesXTS();
void aesCCM();
void des();
void dou_tdes();
void tri_tdes();
/*Create key, iv functions*/
void randomKeyGenerator(int choice);
void ramdomIVGenerator(int choice);
void inputKeyFromScreen(int choice);
void inputIVFromScreen(int choice);
int inputKeyFromFile(int choice);
int inputIVFromFile(int choice);
void chooseKey_IV(int choiceMode);

wstring wplain;
string plain, cipher, encoded, recovered;
byte* key;
byte* key_des;
byte* iv;
int sizeIV = 0, sizeKey = 0;
/*typeOs = 0 when the os is linux and = 1 when the os is window*/
int typeOs;
int main(int argc, char* argv[])
{
    /* Only support input and output in form wstring (wcin, wcout)*/
    #ifdef __linux__
	setlocale(LC_ALL,"");
    typeOs = 0;
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
    typeOs = 1;
	#else
	#endif

	wcout << "*** First, please type input plaintext ***" << endl;
	getline(wcin,wplain);
    if(typeOs)
        wcin.ignore();
    plain=wstring_to_string(wplain);
	
    while(true)
    {
        int choice = 0;
        wcout << "*** Please choose an option below ***" << endl;
        wcout << "   0.Quit"<< endl;
        wcout << "   1. AES modes CBC "<< endl;
        wcout << "   2. AES modes OFB "<< endl;
        wcout << "   3. AES modes CTR "<< endl;
        wcout << "   4. AES modes ECB "<< endl;
        wcout << "   5. AES modes CFB "<< endl;
        wcout << "   6. AES modes GCM "<< endl;
        wcout << "   7. AES modes XTS "<< endl;
        wcout << "   8. AES modes CCM "<< endl;
        wcout << "   9. DES modes CBC "<< endl;
        wcout << "   10. 2-TDES modes CBC "<< endl;
        wcout << "   11. 3-TDES modes CBC "<< endl;
        wcout << "The option number you choose is: ";
        wcin >> choice;
        wcin.ignore();
        wcout << endl;

        switch (choice)
        {
        case 0:
            break;
        case 1:
            chooseKey_IV(choice);
            aesCBC();
            break;
        case 2:
            chooseKey_IV(choice);
            aesOFB();
            break;
        case 3:
            chooseKey_IV(choice);
            aesCTR();
            break;
        case 4:
            chooseKey_IV(choice);
            aesECB();
            break;
        case 5:
            chooseKey_IV(choice);
            aesCFB();
            break;
        case 6:
            chooseKey_IV(choice);
            aesGCM();
            break;
        case 7:
            chooseKey_IV(choice);
            aesXTS();
            break;
        case 8:
            chooseKey_IV(choice);
            aesCCM();
            break;
        case 9:
            chooseKey_IV(choice);
            des();
            break;
        case 10:
            chooseKey_IV(choice);
            dou_tdes();
            break;
        case 11:
            chooseKey_IV(choice);
            tri_tdes();
            break;
        default:
            wcout << "!!! You must choose a number of Algorithm options showing on the screen" << endl;
            break;
        }
    
        string strQuit;
        wstring wstrQuit;
        wcout << "Do you want to quit?(y/n)";
        wcin >> wstrQuit;
        wcin.ignore();
        strQuit = wstring_to_string(wstrQuit);
        if(strQuit == "y")
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
/* Convert interger to wstring*/
wstring integer_to_wstring(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded);
}

void aesCBC()
{
    int start_s = clock();
    int i = 0;
    while (i<10000)
    {
        cipher.clear();
        recovered.clear();
        try
        {
            CBC_Mode< AES >::Encryption e;
            e.SetKeyWithIV(key, sizeKey, iv);
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
            d.SetKeyWithIV(key, sizeKey, iv);
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
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*10000;
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
    wcout << "average execution times in 10000 times: " << etime << " ms" << endl << endl;
}

void aesOFB()
{
	int start_s = clock();
    int i = 0;
    while (i<10000)
    {
        cipher.clear();
        recovered.clear();
        try
        {
            OFB_Mode< AES >::Encryption e;
            e.SetKeyWithIV(key, sizeKey, iv);
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
            d.SetKeyWithIV(key, sizeKey, iv);
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
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*10000;
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
    wcout << "average execution times in 10000 times: " << etime << " ms" << endl << endl;
}

void aesCTR()
{
    int start_s = clock();
    int i = 0;
    while (i<10000)
    {
        cipher.clear();
        recovered.clear();

        try
        {
            CTR_Mode< AES >::Encryption e;
            e.SetKeyWithIV(key, sizeKey, iv);
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
            d.SetKeyWithIV(key, sizeKey, iv);
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
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*10000;
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
    wcout << "average execution times in 10000 times: " << etime << " ms" << endl << endl;
}

void aesECB()
{
    int start_s = clock();
    int i = 0;
    while (i<10000)
    {
        cipher.clear();
        recovered.clear();
        try
        {
            ECB_Mode< AES >::Encryption e;
            e.SetKey(key, sizeKey);
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
            d.SetKey(key, sizeKey);
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
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*10000;
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
    wcout << "average execution times in 10000 times: " << etime << " ms" << endl << endl;
}

void aesCFB()
{
    int start_s = clock();
    int i = 0;
    while (i<10000)
    {
        cipher.clear();
        recovered.clear();
        try
        {
            CFB_Mode< AES >::Encryption e;
            e.SetKeyWithIV(key, sizeKey, iv);
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
            d.SetKeyWithIV(key, sizeKey, iv);
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
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*10000;
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
    wcout << "average execution times in 10000 times: " << etime << " ms" << endl << endl;
}

void aesGCM()
{
    int start_s = clock();
    int i = 0;
    while (i<10000)
    {
        cipher.clear();
        recovered.clear();
        try
        {
            GCM< AES >::Encryption e;
            e.SetKeyWithIV(key, sizeKey, iv, sizeIV);
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
            d.SetKeyWithIV(key, sizeKey, iv, sizeIV);
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
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*10000;
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
    wcout << "average execution times in 10000 times: " << etime << " ms" << endl << endl;
}

void aesXTS()
{
    int start_s = clock();
    int i = 0;
    while (i<10000)
    {
        cipher.clear();
        recovered.clear();
        try
        {
            XTS_Mode< AES >::Encryption enc;
            enc.SetKeyWithIV( key, sizeKey, iv );
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
            dec.SetKeyWithIV( key, sizeKey, iv );
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
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*10000;
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
    wcout << "average execution times in 10000 times: " << etime << " ms" << endl << endl;
}

void aesCCM()
{
    // { 4, 6, 8, 10, 12, 14, 16 }
    const int TAG_SIZE = 8;
    int start_s = clock();
    int i = 0;
    while (i<10000)
    {
        cipher.clear();
        recovered.clear();
        try
        {
            CCM< AES, TAG_SIZE >::Encryption e;
            e.SetKeyWithIV( key, sizeKey, iv, sizeIV );
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
            d.SetKeyWithIV( key, sizeKey, iv, sizeIV );
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
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*10000;
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
    wcout << "average execution times in 10000 times: " << etime << " ms" << endl << endl;
}

void des()
{
    int start_s = clock();
    int i = 0;
    while (i<=10000)
    {
        cipher.clear();
        recovered.clear();
        try
        {
            CBC_Mode< DES >::Encryption e;
            e.SetKeyWithIV(key, sizeKey, iv);

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
            d.SetKeyWithIV(key, sizeKey, iv);

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
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*10000;
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
    wcout << "average execution times in 10000 times: " << etime << " ms" << endl << endl;
}

void dou_tdes()
{
    int start_s = clock();
    int i = 0;
    while (i<=10000)
    {
        cipher.clear();
        recovered.clear();
        try
	    {
		CBC_Mode< DES_EDE2 >::Encryption e;
		e.SetKeyWithIV(key, sizeKey, iv);

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
            d.SetKeyWithIV(key, sizeKey, iv);

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
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*10000;
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
    wcout << "average execution times in 10000 times: " << etime << " ms" << endl << endl;
}

void tri_tdes()
{
    int start_s = clock();
    int i = 0;
    while (i<=10000)
    {
        cipher.clear();
        recovered.clear();
        try
        {

            CBC_Mode< DES_EDE3 >::Encryption e;
            e.SetKeyWithIV(key, sizeKey, iv);

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
            d.SetKeyWithIV(key, sizeKey, iv);

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
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*10000;
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
    wcout << "average execution times in 10000 times: " << etime << " ms" << endl << endl;
}


void randomKeyGenerator(int choice)
{
    if(choice == 9)
    {
        key = new byte[8];
        sizeKey = 8;
    }
    else if(choice == 10)
    {
        key = new byte[16];
        sizeKey = 16;
    }
    else if(choice == 11)
    {
        key = new byte[24];
        sizeKey = 24;
    }
    else{
        key = new byte[32];
        sizeKey = 32;
    }
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, sizeKey);
    encoded.clear();
	StringSource(key, sizeKey, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << sizeKey <<"-bytes key: " << string_to_wstring(encoded) << endl;
}

void ramdomIVGenerator(int choice)
{
    AutoSeededRandomPool prng;
    if(choice == 8)
    {
        wcout << "Maximum Initialization Vector for CCM mode is 13bytes" << endl;
        iv = new byte[13];
        sizeIV = 13;
    }
    else if(choice == 9 || choice == 10 || choice == 11)
    {
        wcout << "Maximum Initialization Vector for DES mode is 8bytes" << endl;
        iv = new byte[8];
        sizeIV = 8;
    }
    else{
        iv = new byte[16];
	    sizeIV = 16;
    }
    prng.GenerateBlock(iv, sizeIV);
    // Pretty print iv
    encoded.clear();
    StringSource(iv, sizeIV, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    wcout << sizeIV <<"-bytes iv: " << string_to_wstring(encoded) << endl;
}

void inputKeyFromScreen(int choice)
{
    wstring wkey;
    string strkey;
    if(choice == 9)
    {
        do{
            if(typeOs)
                wcin.ignore();
            wcout << "Type your Secret key 8-bytes: " << endl;
            getline(wcin, wkey);
            strkey = wstring_to_string(wkey);
        }while(strkey.size() != 8);
        key = new byte[8];
        sizeKey = 8;
    }
    else if(choice == 10)
    {
        do{
            if(typeOs)
                wcin.ignore();
            wcout << "Type your Secret key 16-bytes: " << endl;
            getline(wcin, wkey);
            strkey = wstring_to_string(wkey);
        }while(strkey.size() != 16);
        key = new byte[16];
        sizeKey = 16;
    }
    else if(choice == 11)
    {
        do{
            if(typeOs)
                wcin.ignore();
            wcout << "Type your Secret key 24-bytes: " << endl;
            getline(wcin, wkey);
            strkey = wstring_to_string(wkey);
        }while(strkey.size() != 24);
        key = new byte[24];
        sizeKey = 24;
    }
    else{
        do{
            if(typeOs)
                wcin.ignore();
            wcout << "Type your Secret key 32-bytes: " << endl;
            getline(wcin, wkey);
            strkey = wstring_to_string(wkey);
        }while(strkey.size() != 32);
        key = new byte[32];
        sizeKey = 32;
    }

	StringSource ss(strkey, false);
	CryptoPP::ArraySink copykey(key, sizeKey);
	ss.Detach(new Redirector(copykey));
	ss.Pump(sizeKey); 

    encoded.clear();
	StringSource(key, sizeKey, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << sizeKey <<"-bytes key: " << string_to_wstring(encoded) << endl;
}

void inputIVFromScreen(int choice)
{
    wstring wiv;
    string striv;
    if(choice == 8)
    {
        do{
            if(typeOs)
                wcin.ignore();
            wcout << "Maximum Initialization Vector for CCM mode is 13bytes. \nType your Initial vector 13-bytes: " << endl;
            getline(wcin, wiv);
            striv = wstring_to_string(wiv);
        }while(striv.size() != 13);
        iv = new byte[13];
        sizeIV = 13;
    }
    else if(choice == 9 || choice == 10 || choice == 11)
    {
        do{
            if(typeOs)
                wcin.ignore();
            wcout << "Maximum Initialization Vector for DES is 8bytes. \nType your Initial vector 8-bytes: " << endl;
            getline(wcin, wiv);
            striv = wstring_to_string(wiv);
        }while(striv.size() != 8);
        iv = new byte[8];
        sizeIV = 8;
    }
    else{
        do{
            if(typeOs)
                wcin.ignore();
            wcout << "Type your Initial vector 16-bytes: " << endl;
            getline(wcin, wiv);
            striv = wstring_to_string(wiv);
        }while(striv.size() != 16);
        iv = new byte[16];
        sizeIV = 16;
    }

    StringSource ss(striv, false);
    CryptoPP::ArraySink copyiv(iv, sizeIV);
    ss.Detach(new Redirector(copyiv));
    ss.Pump(sizeIV); 
    
    encoded.clear();
    StringSource(iv, sizeIV, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    wcout << sizeIV <<"-bytes iv: " << string_to_wstring(encoded) << endl;
}

int inputKeyFromFile(int choice)
{
    wstring wfileName;
    string fileName;
    string sub;
    if(typeOs)
        wcin.ignore();
    try{
        if(choice == 9)
        {
            wcout << "Please type 8-bytes key's file name you want to import - [filename].key: " << endl;
            getline(wcin, wfileName);
            fileName = wstring_to_string(wfileName);
            key = new byte[8];
            sizeKey = 8;
        }
        else if(choice == 10)
        {
            wcout << "Please type 16-bytes key's file name you want to import - [filename].key: " << endl;
            getline(wcin, wfileName);
            fileName = wstring_to_string(wfileName);
            key = new byte[16];
            sizeKey = 16;
        }
        else if(choice == 11)
        {
            wcout << "Please type 24-bytes key's file name you want to import - [filename].key: " << endl;
            getline(wcin, wfileName);
            fileName = wstring_to_string(wfileName);
            key = new byte[24];
            sizeKey = 24;
        }
        else{
            wcout << "Please type 32-bytes key's file name you want to import - [filename].key: " << endl;
            getline(wcin, wfileName);
            fileName = wstring_to_string(wfileName);
            key = new byte[32];
            sizeKey = 32;
        }

        const char * c = fileName.c_str();
        FileSource fs(c, false);
        /*Create space  for key*/ 
        CryptoPP::ArraySink copykey(key, sizeKey);
        /*Copy data from AES_key.key  to  key */ 
        fs.Detach(new Redirector(copykey));
        fs.Pump(sizeKey);  // Pump first 32 bytes

        encoded.clear();
        StringSource(key, sizeKey, true,
            new HexEncoder(
                new StringSink(encoded)
            ) // HexEncoder
        ); // StringSource
        wcout << sizeKey <<"-bytes key: " << string_to_wstring(encoded) << endl;
    }
    catch(CryptoPP::FileStore::OpenErr& e)
    {
        cerr << "Caught Error: Do not found a file you typed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        return 1;
    }
    return 0;
}
int inputIVFromFile(int choice)
{
    wstring wfileName;
    string fileName;
    string sub;
    if(typeOs)
        wcin.ignore();
    try{
        if(choice == 8)
        {
            wcout << "Maximum Initialization Vector for CCM mode is 13bytes. \nPlease type iv's file name you want to import - [filename].key: " << endl;
            getline(wcin, wfileName);
            fileName = wstring_to_string(wfileName);
            iv = new byte[13];
            sizeIV = 13;
        }
        else if(choice == 9 || choice == 10 || choice == 11)
        {
            wcout << "Maximum Initialization Vector for DES is 8bytes. \nPlease type iv's file name you want to import - [filename].key: " << endl;
            getline(wcin, wfileName);
            fileName = wstring_to_string(wfileName);
            iv = new byte[8];
            sizeIV = 8;
        }
        else{
            wcout << "Please type iv's file name you want to import - [filename].key: " << endl;
            getline(wcin, wfileName);
            fileName = wstring_to_string(wfileName);
            iv = new byte[16];
            sizeIV = 16;
        }

        const char * c = fileName.c_str();
        FileSource fs(c, false);
        /*Create space  for key*/ 
        CryptoPP::ArraySink copyiv(iv, sizeIV);
        /*Copy data from .key  to  key */ 
        fs.Detach(new Redirector(copyiv));
        fs.Pump(sizeIV);  // Pump first 13 bytes
        
        encoded.clear();
        StringSource(iv, sizeIV, true,
            new HexEncoder(
                new StringSink(encoded)
            ) // HexEncoder
        ); // StringSource
        wcout << sizeIV <<"-bytes iv: " << string_to_wstring(encoded) << endl;
    }
    catch(CryptoPP::FileStore::OpenErr& e)
    {
        cerr << "Caught Error: Do not found a file you typed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        return 1;
    }
    return 0;
}

void chooseKey_IV(int choiceMode)
{
    int choiceKey = 0;
    wcout << "Choose source of Secret key to import:   \n\t1.Ramdom generator  \n\t2.From Screen   \n\t3.From file" <<endl;
    wcin >> choiceKey;
    wcin.ignore();
    switch (choiceKey)
    {
    case 1:
        randomKeyGenerator(choiceMode);
        break;
    case 2:
        inputKeyFromScreen(choiceMode);
        break;
    case 3:
    {
        int checkErr = 0;
        /*do while loop to check error when user select file error*/
        do{
            checkErr = inputKeyFromFile(choiceMode);
        }while(checkErr);
        break;
    }
    default:
        break;
    }
    if(choiceMode != 4)
    {
        int choiceIV = 0;
        wcout << "Choose source of Intinial Vector to import:   \n\t1.Ramdom generator  \n\t2.From Screen   \n\t3.From file" <<endl;
        wcin >> choiceIV;
        wcin.ignore();
        switch (choiceIV)
        {
        case 1:
            ramdomIVGenerator(choiceMode);
            break;
        case 2:
            inputIVFromScreen(choiceMode);
            break;
        case 3:
        {
            int checkErr = 0;
            /*do while loop to check error when user select file error*/
            do{
                checkErr = inputIVFromFile(choiceMode);
            }while(checkErr);
            break;
        }
        default:
            break;
        }
    }
}