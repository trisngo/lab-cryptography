#include <assert.h>
#include <iostream>
using std::wcout;
using std::wcin;
using std::endl;
using std::cerr;

#include <string>
using std::string;
using std::wstring;

#include "include/cryptopp/osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/integer.h"
#include "include/cryptopp/nbtheory.h"
using CryptoPP::Integer;

#include "include/cryptopp/sha.h"
using CryptoPP::SHA1;

#include "include/cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "include/cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::byte;

#include "include/cryptopp/eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "include/cryptopp/oids.h"
using CryptoPP::OID;
// Hex encode, decode
#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <exception>
using std::exception;

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

 // Funtions
wstring string_to_wstring(const std::string &str);
string wstring_to_string(const std::wstring &str);
wstring integer_to_wstring(const CryptoPP::Integer& t);

bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA1>::PrivateKey& key );
bool GeneratePublicKey( const ECDSA<ECP, SHA1>::PrivateKey& privateKey, ECDSA<ECP, SHA1>::PublicKey& publicKey );
void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA1>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA1>::PublicKey& key );
void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA1>::PrivateKey& key );
void LoadPublicKey( const string& filename, ECDSA<ECP, SHA1>::PublicKey& key );

void PrintPrivateKey( const ECDSA<ECP, SHA1>::PrivateKey& key );
void PrintPublicKey( const ECDSA<ECP, SHA1>::PublicKey& key );

bool SignMessage( const ECDSA<ECP, SHA1>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA1>::PublicKey& key, const string& message, const string& signature );

int GenerateKeyPhase();
void SignPhase();
void VerifyPhase();

int osType;

int main(int argc, char* argv[])
{
#ifdef __linux__
    setlocale(LC_ALL, "");
    osType = 1;
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    osType = 2;
#else
#endif
    int option;
    wcout << "Instructions: the program need message file(.txt) and a pair of key file(.key),\nif you do not have key files, you need to generate it first.(option 1)." << endl << endl;
    wcout << "Select phase: " << endl;
    wcout << "1. Generate Keys Phase" << endl;
    wcout << "2. Sign Phase" << endl;
    wcout << "3. Verify Phase" << endl;
    wcin >> option;
    wcin.ignore();
    if (osType == 2)
        wcin.ignore();
    switch (option)
    {
    case 1:
    {
        int check = GenerateKeyPhase();
        if(check != 0) {wcout << "Can not generate key. Try again" << endl;}
        else {wcout << "Generate key successfully. Saved private and public key at the same directory of program." << endl;}
        break;
    }
    case 2:
    {
        SignPhase();
        break;
    }
    case 3:
    {
        VerifyPhase();
        break;
    }
    }
    return 0;
}

/* Def functions*/
/* convert string to wstring */
wstring string_to_wstring(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string(const std::wstring &str)
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

// automatically convert utf8 text file to string, no need convertion phase.
string loadFile(const string &fileName)
{
    string message;
    try{
    FileSource file(fileName.c_str(), true, new StringSink(message));
    }
    catch (const std::exception &e){
        std::cerr << e.what() << endl;
        exit(1);
    }
    return message;
}
int GenerateKeyPhase()
{
    // Scratch result
    bool result = false;   
    // Private and Public keys
    ECDSA<ECP, SHA1>::PrivateKey privateKey;
    ECDSA<ECP, SHA1>::PublicKey publicKey;
    // Generate Keys
    result = GeneratePrivateKey( CryptoPP::ASN1::secp256r1(), privateKey );
    if( !result ) { return -1; }

    result = GeneratePublicKey( privateKey, publicKey );
    if( !result ) { return -2; }
      
    SavePrivateKey( "ec-private.key", privateKey );
    SavePublicKey( "ec-public.key", publicKey );

    PrintPrivateKey( privateKey );
    PrintPublicKey( publicKey );
    return 0;
}

void SignPhase()
{
    wcout << "-----Sign message phase-----" << endl;
    // Private and Public keys
    ECDSA<ECP, SHA1>::PrivateKey privateKey;
    ECDSA<ECP, SHA1>::PublicKey publicKey;
    // Sign and Verify a message      
    wstring wsFileName;
    wcout << "Enter your message's file name: ";
    wcin >> wsFileName;
    if (osType == 2)
        wcin.ignore();
    string fileName = wstring_to_string(wsFileName);
    string message = loadFile(fileName);
    wcout << "Your message :"<< string_to_wstring(message) << endl;

    string signature, encode;
    AutoSeededRandomPool prng;
    // Load secret key
    LoadPrivateKey( "ec-private.key", privateKey);
    // Print parameters //
    wcout << std::hex << "Prime number p=" << integer_to_wstring(privateKey.GetGroupParameters().GetCurve().GetField().GetModulus())<<endl;
    wcout << "Secret key d:" << std::hex << integer_to_wstring(privateKey.GetPrivateExponent()) << endl;
    // Public keys:
    privateKey.MakePublicKey(publicKey);
    
    wcout << "Public key:" << endl;
    wcout << "X:" <<std::hex << integer_to_wstring(publicKey.GetPublicElement().x) << endl;
    wcout << "Y:" <<std::hex << integer_to_wstring(publicKey.GetPublicElement().y) << endl;
    wcout << "-----Waiting for signing-----" << endl;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        //siging message
        signature.erase();
        StringSource( message, true,
            new SignerFilter( prng,
                ECDSA<ECP,SHA1>::Signer(privateKey),
                new HexEncoder(new StringSink(signature))
            )
        );
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    double etime = res/10000;
    /*  kG = (x1, y1), r=x1; s= 𝑘^-1(𝐻(𝑚)+𝑥.𝑟) mod 𝑛 *, h=1, r=s = 2n*/
    wcout << "Total execution 10000 times: " << res << "ms" << endl;
    wcout << "Average execution times is " << etime << " ms" << endl;
    wcout << "Signature (r,s):" << string_to_wstring(signature) << endl;
    wcout << "***Please save this signature in order to verify the message."<< endl;
}

void VerifyPhase()
{
    wcout << "-----Verify signature phase-----" << endl;
    bool result;
    // Verify by any peope: input publicKey, message, signature=(r,s)
    ECDSA<ECP, SHA1>::PublicKey publicKey_r;
    LoadPublicKey("ec-public.key", publicKey_r);
    wcout << "Public key was loaded from file:" << endl;
    wcout << "X:" <<std::hex << integer_to_wstring(publicKey_r.GetPublicElement().x) << endl;
    wcout << "Y:" <<std::hex << integer_to_wstring(publicKey_r.GetPublicElement().y) << endl;

    wstring wsFileName;
    wcout << "Enter your message's file name: ";
    wcin >> wsFileName;
    if (osType == 2)
        wcin.ignore();
    string fileName = wstring_to_string(wsFileName);
    string message_r = loadFile(fileName);
    wcout << "Your message need to verify:"<< string_to_wstring(message_r) << endl;

    string signature;
    wstring wsignature;
    wcout << "Enter signature: ";
    wcin >> wsignature;
    signature = wstring_to_string(wsignature);
    // Hex decode signature
    string signature_r;
    StringSource ss(signature, true,
    new HexDecoder(
        new StringSink(signature_r)
        ) // HexDecoder
    );
    wcout << "-----Waiting for verifying-----" << endl;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        result = VerifyMessage(publicKey_r, message_r, signature_r);
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    double etime = res/10000;
    wcout << "Total execution 10000 times: " << res << "ms" << endl;
    wcout << "Average execution times is " << etime << " ms" << endl;
    wcout << "Verify the signature on m:" << result << endl;
    if(result){
        wcout << "Message signature verification success" << endl;
    }
    else{
        wcout << "Message signature verification failed" << endl;
    }
}

bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA1>::PrivateKey& key )
{
    AutoSeededRandomPool prng;
    key.Initialize( prng, oid );
    assert( key.Validate( prng, 3 ) );
    return key.Validate( prng, 3 );
}

bool GeneratePublicKey( const ECDSA<ECP, SHA1>::PrivateKey& privateKey, ECDSA<ECP, SHA1>::PublicKey& publicKey )
{
    AutoSeededRandomPool prng;
    // Sanity check
    assert( privateKey.Validate( prng, 3 ) );
    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );
    return publicKey.Validate( prng, 3 );
}

void PrintPrivateKey( const ECDSA<ECP, SHA1>::PrivateKey& key )
{   
    wcout << endl;
    wcout << "Private Exponent:" << endl;
    wcout << " " << integer_to_wstring(key.GetPrivateExponent()) << endl; 
}

void PrintPublicKey( const ECDSA<ECP, SHA1>::PublicKey& key )
{   
    wcout << endl;
    wcout << "Public Element:" << endl;
    wcout << " X: " << integer_to_wstring(key.GetPublicElement().x) << endl; 
    wcout << " Y: " << integer_to_wstring(key.GetPublicElement().y) << endl;
}

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA1>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void SavePublicKey( const string& filename, const ECDSA<ECP, SHA1>::PublicKey& key )
{   
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA1>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

void LoadPublicKey( const string& filename, ECDSA<ECP, SHA1>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

bool SignMessage( const ECDSA<ECP, SHA1>::PrivateKey& key, const string& message, string& signature )
{
    AutoSeededRandomPool prng;
    
    signature.erase();    

    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA1>::Signer(key),
            new StringSink( signature )
        ) // SignerFilter
    ); // StringSource
    return !signature.empty();
}

bool VerifyMessage( const ECDSA<ECP, SHA1>::PublicKey& key, const string& message, const string& signature )
{
    bool result = false;

    StringSource( signature+message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP,SHA1>::Verifier(key),
            new ArraySink( (byte*)&result, sizeof(result) )
        ) // SignatureVerificationFilter
    );
    return result;
}
