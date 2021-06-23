/* Hash collection: SHA224, SHA256, SHA384, SHA512, SHA3-224, 
SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 */
#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#include <exception>
using std::exception;

// libs num
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>

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

// Convert integer to wstring
#include <sstream>
using std::ostringstream;

#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h" // SHA3
#include "cryptopp/sha.h"  // SHA1, SHA2
#include "cryptopp/shake.h"// SHAKE

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
// input, output string
#include <cryptopp/filters.h>
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::Redirector;
// input, output file
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

using CryptoPP::byte;

// Def functions
wstring s2ws (const std::string& str);
string ws2s (const std::wstring& str);
wstring in2ws (const CryptoPP::Integer& t);

// Def hash functions
double SHA224(string message);
double SHA256(string message);
double SHA384(string message);
double SHA512(string message);
double SHA3_224(string message);
double SHA3_256(string message);
double SHA3_384(string message);
double SHA3_512(string message);
double SHAKE128(string message);
double SHAKE256(string message);

int osType;

int main (int argc, char* argv[])
{
    #ifdef __linux__
	    setlocale(LC_ALL,"");
        osType = 1;
	#elif _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
        osType = 2;
	#else
	#endif
    // Input message
    int option;
    wcout << "***Select option to input: " << endl;
    wcout << "1.From screen" << endl;
    wcout << "2.From file" << endl;
    wcin >> option;
    wcin.ignore();
    if (osType == 2)
        wcin.ignore();
    string message;
    switch (option)
    {
    case 1:
        {
            wstring wsmessage;
            wcout << "Enter your message input: ";
            std::getline(wcin, wsmessage);
            message = ws2s(wsmessage);
            break;
        }
    case 2:
        {
            wstring wsFileName;
            wcout << "Enter your message's file name: ";
            wcin >> wsFileName;
            if (osType == 2)
                wcin.ignore();
            string fileName = ws2s(wsFileName);
            // Load message from a file
            try{
            FileSource file(fileName.c_str(), true, new StringSink(message));
            }
            catch (const std::exception &e){
                std::cerr << e.what() << endl;
                exit(1);
            }

            wcout << "Message read from file: " << s2ws(message) << endl;
            break;
        }
    }
   
    // Compution
    double res = 0;
    int optionAlg;
    wcout << "\n***Select option of secure hash algorithm: " << endl;
    wcout << " 1.SHA224\n 2.SHA256\n 3.SHA384\n 4.SHA512\n 5.SHA3-224\n 6.SHA3-256\n 7.SHA3-384\n 8.SHA3-512\n 9.SHAKE128\n 10.SHAKE256" << endl;
    wcin >> optionAlg;
    wcin.ignore();
    if (osType == 2)
        wcin.ignore();
    switch (optionAlg)
    {
    case 1:
        res = SHA224(message);
        break;
    case 2:
        res = SHA256(message);
        break;
    case 3:
        res = SHA384(message);
        break;
    case 4:
        res = SHA512(message);
        break;
    case 5:
        res = SHA3_224(message);
        break;
    case 6:
        res = SHA3_256(message);
        break;
    case 7:
        res = SHA3_384(message);
        break;
    case 8:
        res = SHA3_512(message);
        break;
    case 9:
        res = SHAKE128(message);
        break;
    case 10:
        res = SHAKE256(message);
        break;
    default:
        break;
    }
    
    // Result of the compution
    double etime = res/10000;
    wcout << "Total execution 10000 times: " << res << " ms" << endl;
    wcout << "Average execution times is " << etime << " ms" << endl;
    return 0; 
}

double SHA224(string message)
{
    CryptoPP::SHA224 hash;
    // Information of the hash algorithms	
    wcout << "\n*/*/*/*/*/*" << endl;
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    // message, ouput digest 
    wcout << "Message: " << s2ws(message) << endl;
    string digest;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        // Input for hash function hash
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size());
        digest.resize(hash.DigestSize());
        // Compute output hash.Final or hash.TruncatedFinal
        hash.TruncatedFinal((byte*)&digest[0],digest.size());
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    // Pretty pringt output
    wcout << "Digest: ";
    string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    wcout << s2ws(encode) << endl;
    return res;
}

double SHA256(string message)
{
    CryptoPP::SHA256 hash;
    // Information of the hash algorithms	
    wcout << "\n*/*/*/*/*/*" << endl;
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    // message, ouput digest 
    wcout << "Message: " << s2ws(message) << endl;
    string digest;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        // Input for hash function hash
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size());
        digest.resize(hash.DigestSize());
        // Compute output hash.Final or hash.TruncatedFinal
        hash.TruncatedFinal((byte*)&digest[0],digest.size());
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    // Pretty pringt output
    wcout << "Digest: ";
    string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    wcout << s2ws(encode) << endl;
    return res;
}

double SHA384(string message)
{
    CryptoPP::SHA384 hash;
    // Information of the hash algorithms	
    wcout << "\n*/*/*/*/*/*" << endl;
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    // message, ouput digest 
    wcout << "Message: " << s2ws(message) << endl;
    string digest;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        // Input for hash function hash
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size());
        digest.resize(hash.DigestSize());
        // Compute output hash.Final or hash.TruncatedFinal
        hash.TruncatedFinal((byte*)&digest[0],digest.size());
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    // Pretty pringt output
    wcout << "Digest: ";
    string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    wcout << s2ws(encode) << endl;
    return res;
}

double SHA512(string message)
{
    CryptoPP::SHA512 hash;
    // Information of the hash algorithms	
    wcout << "\n*/*/*/*/*/*" << endl;
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    // message, ouput digest 
    wcout << "Message: " << s2ws(message) << endl;
    string digest;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        // Input for hash function hash
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size());
        digest.resize(hash.DigestSize());
        // Compute output hash.Final or hash.TruncatedFinal
        hash.TruncatedFinal((byte*)&digest[0],digest.size());
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    // Pretty pringt output
    wcout << "Digest: ";
    string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    wcout << s2ws(encode) << endl;
    return res;
}

double SHA3_224(string message)
{
    CryptoPP::SHA3_224 hash;
    // Information of the hash algorithms	
    wcout << "\n*/*/*/*/*/*" << endl;
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    // message, ouput digest 
    wcout << "Message: " << s2ws(message) << endl;
    string digest;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        // Input for hash function hash
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size());
        digest.resize(hash.DigestSize());
        // Compute output hash.Final or hash.TruncatedFinal
        hash.TruncatedFinal((byte*)&digest[0],digest.size());
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    // Pretty pringt output
    wcout << "Digest: ";
    string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    wcout << s2ws(encode) << endl;
    return res;
}

double SHA3_256(string message)
{
    CryptoPP::SHA3_256 hash;
    // Information of the hash algorithms	
    wcout << "\n*/*/*/*/*/*" << endl;
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    // message, ouput digest 
    wcout << "Message: " << s2ws(message) << endl;
    string digest;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        // Input for hash function hash
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size());
        digest.resize(hash.DigestSize());
        // Compute output hash.Final or hash.TruncatedFinal
        hash.TruncatedFinal((byte*)&digest[0],digest.size());
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    // Pretty pringt output
    wcout << "Digest: ";
    string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    wcout << s2ws(encode) << endl;
    return res;
}
double SHA3_384(string message)
{
    CryptoPP::SHA3_384 hash;
    // Information of the hash algorithms	
    wcout << "\n*/*/*/*/*/*" << endl;
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    // message, ouput digest 
    wcout << "Message: " << s2ws(message) << endl;
    string digest;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        // Input for hash function hash
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size());
        digest.resize(hash.DigestSize());
        // Compute output hash.Final or hash.TruncatedFinal
        hash.TruncatedFinal((byte*)&digest[0],digest.size());
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    // Pretty pringt output
    wcout << "Digest: ";
    string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    wcout << s2ws(encode) << endl;
    return res;
}

double SHA3_512(string message)
{
    CryptoPP::SHA3_512 hash;
    // Information of the hash algorithms	
    wcout << "\n*/*/*/*/*/*" << endl;
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    // message, ouput digest 
    wcout << "Message: " << s2ws(message) << endl;
    string digest;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        // Input for hash function hash
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size());
        digest.resize(hash.DigestSize());
        // Compute output hash.Final or hash.TruncatedFinal
        hash.TruncatedFinal((byte*)&digest[0],digest.size());
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    // Pretty pringt output
    wcout << "Digest: ";
    string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    wcout << s2ws(encode) << endl;
    return res;
}

double SHAKE128(string message)
{
    CryptoPP::SHAKE128 hash;
    // Information of the hash algorithms	
    wcout << "\n*/*/*/*/*/*" << endl;
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    // message, ouput digest 
    wcout << "Message: " << s2ws(message) << endl;
    string digest;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        // Input for hash function hash
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size());
        digest.resize(hash.DigestSize());
        // Compute output hash.Final or hash.TruncatedFinal
        hash.TruncatedFinal((byte*)&digest[0],digest.size());
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    // Pretty pringt output
    wcout << "Digest: ";
    string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    wcout << s2ws(encode) << endl;
    return res;
}
double SHAKE256(string message)
{
    CryptoPP::SHAKE256 hash;
    // Information of the hash algorithms	
    wcout << "\n*/*/*/*/*/*" << endl;
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    // message, ouput digest 
    wcout << "Message: " << s2ws(message) << endl;
    string digest;
    int start_s = clock();
    int i = 0;
    while(i < 10000)
    {
        // Input for hash function hash
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size());
        digest.resize(hash.DigestSize());
        // Compute output hash.Final or hash.TruncatedFinal
        hash.TruncatedFinal((byte*)&digest[0],digest.size());
        i++;
    }
    int stop_s = clock();
    double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
    // Pretty pringt output
    wcout << "Digest: ";
    string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    wcout << s2ws(encode) << endl;
    return res;
}

/* convert string to wstring */
wstring s2ws(const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string ws2s(const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

wstring in2ws (const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded);
}