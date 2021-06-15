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
#include <fstream>
using std::ofstream;

/*Reading key from file*/
#include "./include/cryptopp/queue.h"
using CryptoPP::ByteQueue;
#include "./include/cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

wstring string_to_wstring(const std::string &str);
string wstring_to_string(const std::wstring &str);

void Load(const string &filename, BufferedTransformation &bt);
void LoadPrivateKey(const string &filename, PrivateKey &key);
void LoadPublicKey(const string &filename, PublicKey &key);
void RSAEncryption();
void RSADecryption();

int osType;

int main(int argc, char *argv[])
{
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
// Plaintext:- Support Vietnamese (UTF-16) - Input from screen or from file (using switch case)- The keys load from files- The public key: >= 3072 bits
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
        wcout << "Enter your plain text file name: ";
        wcin >> wsFileName;
        if (osType == 2)
            wcin.ignore();
        string fileName = wstring_to_string(wsFileName);

        // //Read vietnamese text from file into string
        // std::wifstream wif(fileName);
        // wif.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
        // //if the above command give you an error, try the this command below
        // //wif.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));
        // std::wstringstream wss;
        // wss << wif.rdbuf();
        // plain = wstring_to_string(wss.str());
        try{
        FileSource file(fileName.c_str(), true, new StringSink(plain));
        }
        catch (const std::exception &e){
            std::cerr << e.what() << endl;
            exit(1);
        }
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

        int start_s = clock();
        int i = 0;
        cipher.clear();
        while(i < 10000)
        {
            cipher.clear();
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
            );  
            i++;
        }
        int stop_s = clock();
        double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
        double etime = res/10000;
        wcout << "Cipher text: " << string_to_wstring(encoded) << "\nYour cipher text was written to cipher.txt." << endl;
        ofstream outfile;
        outfile.open("cipher.txt", std::ios::trunc);//std::ios::trunc
        outfile << encoded; 

        wcout << "Total execution 10000 times: " << res << " ms" << endl;
        wcout << "Average execution times is " << etime << " ms" << endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << endl;
        exit(1);
    }
}
//Cyphertext:- Input from screen or from file (using switch case) - The keys load from files
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
            // std::ifstream readStream;
            // readStream.open(cipherFileName);
            // std::getline(readStream, hexCipher);
            try{
            FileSource file(cipherFileName.c_str(), true, new StringSink(hexCipher));
            }
            catch (const std::exception &e){
                std::cerr << e.what() << endl;
                exit(1);
            }
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

        int start_s = clock();
        int i = 0;
        while(i < 10000)
        {
            cipher.clear();
            recovered.clear();
            AutoSeededRandomPool rng;
            RSA::PrivateKey privateKey;
            LoadPrivateKey(fileName, privateKey);
            RSAES_OAEP_SHA_Decryptor d(privateKey);
            StringSource ss(hexCipher, true, new HexDecoder(new StringSink(cipher)));
            StringSource(cipher, true,
                        new PK_DecryptorFilter(rng, d,
                                                new StringSink(recovered)) // PK_EncryptorFilter
            );
            i++;
        }
        int stop_s = clock();
        double res = ((stop_s - start_s)/(double(CLOCKS_PER_SEC)))*1000;
        double etime = res/10000;
        wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
        wcout << "Total execution 10000 times: " << res << "ms" << endl;
        wcout << "Average execution times is " << etime << " ms" << endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        exit(1);
    }
}