#include <chrono>
using namespace std::chrono;

#include "include/cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "include/cryptopp/sha.h"
using CryptoPP::SHA1;

#include "include/cryptopp/filters.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "include/cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "include/cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include "include/cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <string>
using std::string;
using std::wstring;

#include <exception>
using std::exception;

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

#include <assert.h>

/* Set _setmode()*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <sstream>
#else
#endif
/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

wstring string_to_wstring(const std::string &str);
string wstring_to_string(const std::wstring &str);

/*Reading key from file*/
#include "./include/cryptopp/queue.h"
using CryptoPP::ByteQueue;
#include "./include/cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

void Load(const string &filename, BufferedTransformation &bt);
void LoadPrivateKey(const string &filename, PrivateKey &key);
void LoadPublicKey(const string &filename, PublicKey &key);
void RSAEncryption();
void RSADecryption();

int osType;

int main(int argc, char *argv[])
{
    //try
    //{
/*Set mode support Vietnamese*/
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
    wcout << "Select mode: " << endl;
    wcout << "1.Encryption" << endl;
    wcout << "2.Decryption" << endl;
    wcin >> option;
    wcin.ignore();
    if (osType == 2)
        wcin.ignore();
    switch (option)
    {
    case 1:
    {
        RSAEncryption();
        break;
    }
    case 2:
    {
        RSADecryption();
        break;
    }
    }
    return 0;
}

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

void LoadPrivateKey(const string &filename, PrivateKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void LoadPublicKey(const string &filename, PublicKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void Load(const string &filename, BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

void RSAEncryption()
{
    int option;
    wcout << "How do you want to enter you plaintext?" << endl;
    wcout << "1.From screen" << endl;
    wcout << "2.From file" << endl;
    wcin >> option;
    wcin.ignore();
    if (osType == 2)
        wcin.ignore();
    string plain, cipher, encoded;
    switch (option)
    {
    case 1:
    {
        wstring wsplain;
        wcout << "Enter your message: ";
        getline(wcin, wsplain);
        if (osType == 2)
            wcin.ignore();
        plain = wstring_to_string(wsplain);
        break;
    }
    case 2:
    {
        wstring wsFileName;
        wcout << "Enter your message file name: ";
        wcin >> wsFileName;
        if (osType == 2)
            wcin.ignore();
        string fileName = wstring_to_string(wsFileName);
        //Read vietnamese text from file into string
        std::wifstream wif(fileName);
        wif.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
        //if the above command give you an error, try the this command below
        //wif.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));
        std::wstringstream wss;
        wss << wif.rdbuf();
        plain = wstring_to_string(wss.str());
        wcout << "Plain text read from file: " << string_to_wstring(plain) << endl;
        break;
    }
    }
    try
    {
        RSA::PublicKey publicKey;
        wcout << "Enter your public key file name: ";
        wstring wsFileName;
        wcin >> wsFileName;
        if (osType == 2)
            wcin.ignore();
        string fileName = wstring_to_string(wsFileName);
        LoadPublicKey(fileName, publicKey);
        auto start = high_resolution_clock::now();
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Encryptor e(publicKey);
        StringSource(plain, true,
                     new PK_EncryptorFilter(rng, e,
                                            new StringSink(cipher)) // PK_EncryptorFilter
        );                                                          // StringSource
                                                                    /* Pretty Print cipher text */
        encoded.clear();
        StringSource(cipher, true,
                     new HexEncoder(
                         new StringSink(encoded)) // HexEncoder
        );                                        // StringSource
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        wcout << "Cipher text at hex: " << string_to_wstring(encoded) << endl;
        wcout << "Average execution times is " << duration.count() << " microseconds" << endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        exit(1);
    }
}

void RSADecryption()
{
    int option;
    wcout << "How do you want to enter your ciphertext?" << endl;
    wcout << "1.From screen" << endl;
    wcout << "2.From file" << endl;
    wcin >> option;
    wcin.ignore();
    if (osType == 2)
        wcin.ignore();
    string cipher, recovered, hexCipher;
    switch (option)
    {
    case 1:
    {
        try
        {
            wstring wsHexCipher;
            wcout << "Enter ciphertext: ";
            wcin >> wsHexCipher;
            if (osType == 2)
                wcin.ignore();
            //cipher chua decoded string cua cipher
            hexCipher = wstring_to_string(wsHexCipher);
            break;
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
            exit(1);
        }
    }
    case 2:
    {
        wcout << "Enter your cipher text file name: ";
        wstring wsCipherFileName;
        wcin >> wsCipherFileName;
        if (osType == 2)
            wcin.ignore();
        string cipherFileName = wstring_to_string(wsCipherFileName);
        std::ifstream readStream;
        readStream.open(cipherFileName);
        std::getline(readStream, hexCipher);
        wcout << "Hex cipher text read from file: " << string_to_wstring(hexCipher) << endl;
        break;
    }
    }
    try
    {
        wcout << "Enter your private key file name: ";
        wstring wsFileName;
        wcin >> wsFileName;
        if (osType == 2)
            wcin.ignore();
        string fileName = wstring_to_string(wsFileName);
        auto start = high_resolution_clock::now();
        AutoSeededRandomPool rng;
        RSA::PrivateKey privateKey;
        LoadPrivateKey(fileName, privateKey);
        RSAES_OAEP_SHA_Decryptor d(privateKey);
        StringSource ss(hexCipher, true, new HexDecoder(new StringSink(cipher)));
        StringSource(cipher, true,
                     new PK_DecryptorFilter(rng, d,
                                            new StringSink(recovered)) // PK_EncryptorFilter
        );
        auto stop = high_resolution_clock::now();
        wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
        auto duration = duration_cast<microseconds>(stop - start);
        wcout << "Average execution times is " << duration.count() << " microseconds" << endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        exit(1);
    }
}