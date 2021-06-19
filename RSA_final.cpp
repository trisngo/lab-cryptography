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
void SaveKey(const RSA::PublicKey &PublicKey, const string &filename);
void SaveKey(const RSA::PrivateKey &PrivateKey, const string &filename);
void RSAEncryptionMode();
void RSADecryptionMode();
int GenerateKey();

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
    wcout << "0.Generate keys" << endl;
    wcout << "1.Encryption" << endl;
    wcout << "2.Decryption" << endl;
    wcin >> option;
    wcin.ignore();
    if (osType == 2)
        wcin.ignore();
    switch (option)
    {
    case 0:
    {
        int check = GenerateKey();
        if(check != 0) {wcout << "Can not generate key. Try again" << endl;}
        else {wcout << "Generate key successfully. Saved private and public key at the same directory of program." << endl;}
        break;
    }
    case 1:
    {
        RSAEncryptionMode();
        break;
    }
    case 2:
    {
        RSADecryptionMode();
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

void SaveKey(const RSA::PublicKey &PublicKey, const string &filename)
{
    // DER Encode Key - X.509 key format
    PublicKey.Save(
        FileSink(filename.c_str(), true /*binary*/).Ref());
}

void SaveKey(const RSA::PrivateKey &PrivateKey, const string &filename)
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Save(
        FileSink(filename.c_str(), true /*binary*/).Ref());
}

int GenerateKey()
{
    wcout << "-----Generate keys-----" << endl;
    AutoSeededRandomPool rnd;
    try
    {
        RSA::PrivateKey rsaPrivate;
        rsaPrivate.GenerateRandomWithKeySize(rnd, 3072);

        RSA::PublicKey rsaPublic(rsaPrivate);

        SaveKey(rsaPrivate, "rsa-private.key");
        SaveKey(rsaPublic, "rsa-public.key");
    }

    catch (CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        return -2;
    }

    catch (std::exception &e)
    {
        cerr << e.what() << endl;
        return -1;
    }

    return 0;
}

void RSAEncryptionMode()
{
    wcout << "-----Encryption Mode-----" << endl;
    int option;
    wcout << "Select option to input: " << endl;
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
        wcout << "Enter your plain text's file name: ";
        wcin >> wsFileName;
        if (osType == 2)
            wcin.ignore();
        string fileName = wstring_to_string(wsFileName);
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
        wcout << "Enter your public key's file name: ";
        wstring wsFileName;
        wcin >> wsFileName;
        if (osType == 2)
            wcin.ignore();
        string fileName = wstring_to_string(wsFileName);
        LoadPublicKey(fileName, publicKey);
        wcout << "-----Waiting-----" << endl;
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
        wcout << "Cipher text: " << string_to_wstring(encoded) << "\nYour cipher text was written to rsa-cipher.txt ." << endl;
        ofstream outfile;
        outfile.open("rsa-cipher.txt", std::ios::trunc);//std::ios::trunc
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

void RSADecryptionMode()
{
    wcout << "-----Decryption Mode-----" << endl;
    int option;
    wcout << "Select option to input: " << endl;
    wcout << "1.From screen" << endl;
    wcout << "2.From file" << endl;
    wcin >> option;
    wcin.ignore();
    if (osType == 2)
        wcin.ignore();
    string cipher, recovered, cipherInHex;
    switch (option)
    {
        case 1:
        {
            try
            {
                wstring wsCipherInHex;
                wcout << "Enter ciphertext: ";
                wcin >> wsCipherInHex;
                if (osType == 2)
                    wcin.ignore();
                cipherInHex = wstring_to_string(wsCipherInHex);
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
            wcout << "Enter your cipher text's file name: ";
            wstring wsCipherFileName;
            wcin >> wsCipherFileName;
            if (osType == 2)
                wcin.ignore();
            string cipherFileName = wstring_to_string(wsCipherFileName);
            
            try{
            FileSource file(cipherFileName.c_str(), true, new StringSink(cipherInHex));
            }
            catch (const std::exception &e){
                std::cerr << e.what() << endl;
                exit(1);
            }
            wcout << "Cipher text read from file: " << string_to_wstring(cipherInHex) << endl;
            break;
        }
    }
    try
    {
        wcout << "Enter your private key's file name: ";
        wstring wsFileName;
        wcin >> wsFileName;
        if (osType == 2)
            wcin.ignore();
        string fileName = wstring_to_string(wsFileName);

        wcout << "-----Waiting-----" << endl;
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
            StringSource ss(cipherInHex, true, new HexDecoder(new StringSink(cipher)));
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