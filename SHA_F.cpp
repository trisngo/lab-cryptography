/* Hash to string
h:{0,1}^* --> {0,1}^l, l is digest size */
#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>

/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

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
#include <iostream>
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

int main (int argc, char* argv[])
{
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif
    CryptoPP::SHA3_512 hash;
    // Information of the hash algorithms	
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    // Input message, ouput digest 
    string message, digest;
    wstring wsmessage;
    wcout << L"Nhập message đầu vào:";
    std::getline(wcin, wsmessage);
    message = ws2s(wsmessage);
    // Input for hash function hash
    hash.Restart();
    hash.Update((const byte*)message.data(), message.size());
    digest.resize(hash.DigestSize());
    // Compute output hash.Final or hash.TruncatedFinal
    hash.TruncatedFinal((byte*)&digest[0],digest.size());
    // Pretty pringt output
    wcout << "Message: " << wsmessage << endl;
    wcout << "Digest: ";
    string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    // Convert diset to integer;
    encode = encode+"H";
    CryptoPP::Integer Idigest(encode.data());
    // Conver to number in Z_p
    CryptoPP::Integer p("ffffffff00000001000000000000000000000000ffffffffffffffffffffffffh");
    Idigest=Idigest % p;
    wcout << in2ws(Idigest) << std::endl;
    return 0; 
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