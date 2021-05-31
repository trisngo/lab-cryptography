#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
using std::cerr;
#include <string>
using std::string;

#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "include/cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/ccm.h"
using CryptoPP::CCM;

#include "assert.h"
using CryptoPP::byte;


int main(int argc, char* argv[])
{
    // The test vectors use both ADATA and PDATA. However,
    //  as a drop in replacement for older modes such as
    //  CBC, we only exercise (and need) plain text.

    AutoSeededRandomPool prng;

    byte key[ AES::DEFAULT_KEYLENGTH ];
    prng.GenerateBlock( key, sizeof(key) );

    // { 7, 8, 9, 10, 11, 12, 13 }
    byte iv[ 12 ];
    prng.GenerateBlock( iv, sizeof(iv) );    

    // { 4, 6, 8, 10, 12, 14, 16 }
    const int TAG_SIZE = 8;

    string pdata="Authenticated Encryption";

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string rpdata;

    /*********************************\
    \*********************************/

    // Pretty print
    encoded.clear();
    StringSource( key, sizeof(key), true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    cout << "key: " << encoded << endl;

    // Pretty print
    encoded.clear();
    StringSource( iv, sizeof(iv), true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    cout << " iv: " << encoded << endl;

    cout << endl;

    /*********************************\
    \*********************************/

    try
    {
        cout << "plain text: " << pdata << endl;

        CCM< AES, TAG_SIZE >::Encryption e;
        e.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        e.SpecifyDataLengths( 0, pdata.size(), 0 );

        StringSource( pdata, true,
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
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    // Pretty print
    encoded.clear();
    StringSource( cipher, true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    cout << "cipher text: " << encoded << endl;

    // Attack the first and last byte
    //if( cipher.size() > 1 )
    //{
    // cipher[ 0 ] |= 0x0F;
    // cipher[ cipher.size()-1 ] |= 0x0F;
    //}

    /*********************************\
    \*********************************/

    try
    {
        CCM< AES, TAG_SIZE >::Decryption d;
        d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );

        AuthenticatedDecryptionFilter df( d,
            new StringSink( rpdata )
        ); // AuthenticatedDecryptionFilter

        // The StringSource dtor will be called immediately
        //  after construction below. This will cause the
        //  destruction of objects it owns. To stop the
        //  behavior so we can get the decoding result from
        //  the DecryptionFilter, we must use a redirector
        //  or manually Put(...) into the filter without
        //  using a StringSource.
        StringSource( cipher, true,
            new Redirector( df /*, PASS_EVERYTHING */ )
        ); // StringSource

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity

        cout << "recovered text: " << rpdata << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    return 0;
}
