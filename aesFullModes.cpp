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
using std::cin;//dung gi call len de giam dung luong cung nhu bugs
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

#include "include/cryptopp/hex.h"//convert string to hex
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "include/cryptopp/filters.h"//nhan input tung string vao dong thanh dang buffer, co the them ArraySink, ArraySource
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/modes.h"
#include "include/cryptopp/ccm.h"
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

string plain, cipher, encoded, recovered;
byte key[AES::MAX_KEYLENGTH];
byte iv[AES::BLOCKSIZE];

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

        #if 0
                StreamTransformationFilter filter(e);
                filter.Put((const byte*)plain.data(), plain.size());
                filter.MessageEnd();

                const size_t ret = filter.MaxRetrievable();
                cipher.resize(ret);
                filter.Get((byte*)cipher.data(), cipher.size());
        #endif
	    }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            exit(1);
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

            #if 0
                    StreamTransformationFilter filter(d);
                    filter.Put((const byte*)cipher.data(), cipher.size());
                    filter.MessageEnd();

                    const size_t ret = filter.MaxRetrievable();
                    recovered.resize(ret);
                    filter.Get((byte*)recovered.data(), recovered.size());
            #endif
	    }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            exit(1);
        }
        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    cout << "*** This is AES CBC mode ***" << endl;
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

void aesOFB()
{
    // int start_s = clock();
    // int i = 0;
    // while (i<1000)
    // {
        // cipher.clear();
        // recovered.clear();

        //i++;
    //     }
    // int stop_s = clock();
    // double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    // cout << "plain text: " << plain << endl;
    // // Pretty print
    // encoded.clear();
    // StringSource(cipher, true,
    //     new HexEncoder(
    //         new StringSink(encoded)
    //     ) // HexEncoder
    // ); // StringSource
    // cout << "*** This is AES OFB mode ***" << endl;
    // cout << "cipher text: " << encoded << endl;
    // cout << "recovered text: " << recovered << endl;
    // cout << "average execution times in 1000 times: " << etime << " ms" << endl;
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
            exit(1);
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
            exit(1);
        }
        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    cout << "*** This is AES OFB mode ***" << endl;
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
            exit(1);
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
            exit(1);
        }

        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    cout << "*** This is AES CTR mode ***" << endl;
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
            exit(1);
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
            exit(1);
        }
        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    cout << "*** This is AES ECB mode ***" << endl;
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
            exit(1);
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
            exit(1);
        }
        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    cout << "*** This is AES CFB mode ***" << endl;
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
            exit(1);
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
            exit(1);
        }

        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    cout << "*** This is AES GCM mode ***" << endl;
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

            #if 0
                    std::cout << "key length: " << enc.DefaultKeyLength() << std::endl;
                    std::cout << "key length (min): " << enc.MinKeyLength() << std::endl;
                    std::cout << "key length (max): " << enc.MaxKeyLength() << std::endl;
                    std::cout << "block size: " << enc.BlockSize() << std::endl;
            #endif

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
            exit(1);
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
            exit(1);
        }
        i++;
    }
    int stop_s = clock();
    double etime = (stop_s - start_s)/double(CLOCKS_PER_SEC)*1000;
    cout << "*** This is AES XTS mode ***" << endl;
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
	AutoSeededRandomPool prng;//tao chuoi bit random, dau ra la byte

	prng.GenerateBlock(key, sizeof(key));

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
	cout << "key: " << encoded << endl;
	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl << endl;
    int choice = 0;
    while (true)
    {
        cout << "*** Please choose an option below ***" << endl;
        cout << "   0. Quit "<< endl;
        cout << "   1. AES modes CBC "<< endl;
        cout << "   2. AES modes OFB "<< endl;
        cout << "   3. AES modes CTR "<< endl;
        cout << "   4. AES modes ECB "<< endl;
        cout << "   5. AES modes CFB "<< endl;
        cout << "   6. AES modes GCM "<< endl;
        cout << "   7. AES modes XTS "<< endl;
        cout << "The number of options you choose is: ";
        cin >> choice;
        cout << endl;
        switch (choice)
        {
        case 0:
            cout << "Good bye." << endl;
            return 0;
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
        default:
            cout << "!!! You must choose a number of Algorithm option showing on the screen" << endl;
            break;
        }
    }
	return 0;
}