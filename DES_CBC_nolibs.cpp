#include <bits/stdc++.h>

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

#include <fstream>
#include <bitset>
#include <string>
using std::unordered_map;
using std::vector;
using std::stringstream;
using std::bitset;
#include <ctime>
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
string hex2bin(string s);
string bin2hex(string s);
string Str2Hex(string str);
string str2Hex(string str);
string hex2String(const std::string& input);
string permute(string k, int *arr, int n);
string shift_left(string k, int shifts);
string xor_(string a, string b);
string encrypt(string pt, vector<string> rkb, vector<string> rk);
string encryptCBC(string plain, string iv, vector<string> rkb, vector<string> rk);
string decryptCBC(string cipher, string iv, vector<string> rkb, vector<string> rk);

//  Tables for plain text 
//  Initial permutation (IP) Table
int IP[] = {58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6,
			64, 56, 48, 40, 32, 24, 16, 8,
			57, 49, 41, 33, 25, 17, 9,  1,
			59, 51, 43, 35, 27, 19, 11, 3,
			61, 53, 45, 37, 29, 21, 13, 5,
			63, 55, 47, 39, 31, 23, 15, 7};

//  Final Initial permutation (IP_1)Table
int IP_1[] = {40, 8, 48, 16, 56, 24, 64, 32,
			  39, 7, 47, 15, 55, 23, 63, 31,
			  38, 6, 46, 14, 54, 22, 62, 30,
			  37, 5, 45, 13, 53, 21, 61, 29,
			  36, 4, 44, 12, 52, 20, 60, 28,
			  35, 3, 43, 11, 51, 19, 59, 27,
			  34, 2, 42, 10, 50, 18, 58, 26,
			  33, 1, 41,  9, 49, 17, 57, 25};


/*Tables for create key*/
// Parity bit drop table,Permution create key, 64-bit key to 56-bit key
int PC_1[] = {57, 49, 41, 33, 25, 17, 9,
			   1, 58, 50, 42, 34, 26, 18,
			  10,  2, 59, 51, 43, 35, 27,
			  19, 11,  3, 60, 52, 44, 36,
			  63, 55, 47, 39, 31, 23, 15,
			   7, 62, 54, 46, 38, 30, 22,
			  14,  6, 61, 53, 45, 37, 29,
			  21, 13,  5, 28, 20, 12,  4}; 

// Key- Compression Table.Compress 56-bit key to 48-bit key
int PC_2[] = {14, 17, 11, 24,  1,  5,
			   3, 28, 15,  6, 21, 10,
			  23, 19, 12,  4, 26,  8,
			  16,  7, 27, 20, 13,  2,
			  41, 52, 31, 37, 47, 55,
			  30, 40, 51, 45, 33, 48,
			  44, 49, 39, 56, 34, 53,
			  46, 42, 50, 36, 29, 32};

// Number of bits shifts
int shiftTable[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};


/*Table use for Encryption function*/
// Expansion Table
int E[] = {32,  1,  2,  3,  4,  5,
		    4,  5,  6,  7,  8,  9,
		    8,  9, 10, 11, 12, 13,
		   12, 13, 14, 15, 16, 17,
		   16, 17, 18, 19, 20, 21,
		   20, 21, 22, 23, 24, 25,
		   24, 25, 26, 27, 28, 29,
		   28, 29, 30, 31, 32,  1};

// S-Box table
int S_BOX[8][4][16] = {
	{  
		{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},  
		{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},  
		{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0}, 
		{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} 
	},
	{  
		{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},  
		{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5}, 
		{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},  
		{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}  
	}, 
	{  
		{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},  
		{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},  
		{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},  
		{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}  
	}, 
	{  
		{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},  
		{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},  
		{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},  
		{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}  
	},
	{  
		{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},  
		{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},  
		{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},  
		{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}  
	},
	{  
		{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},  
		{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},  
		{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},  
		{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}  
	}, 
	{  
		{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},  
		{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},  
		{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},  
		{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}  
	}, 
	{  
		{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},  
		{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},  
		{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},  
		{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}  
	} 
};

// Straight Permutation Table
int P[] = {16,  7, 20, 21,
		   29, 12, 28, 17,
		    1, 15, 23, 26,
		    5, 18, 31, 10,
		    2,  8, 24, 14,
		   32, 27,  3,  9,
		   19, 13, 30,  6,
		   22, 11,  4, 25 };

int main()
{
    int typeOs;
    #ifdef __linux__
	setlocale(LC_ALL,"");
    typeOs = 0;
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
    typeOs = 1;
	#else
	#endif
    
    string plain, key, iv;
    wstring wsplain, wskey, wsiv;
    wcout<<"Please enter your plain text: ";
    getline(wcin, wsplain);
    if(typeOs)
        wcin.ignore();
    plain = wstring_to_string(wsplain);
    //if the input is not divisible to 8 (byte), adding more byte
    while(plain.length() % 8 != 0)
    {
        plain+= " ";
    }
    plain = str2Hex(plain);
    wcout << "Your plain text at hex: " << string_to_wstring(plain) << endl;
    wcout<<"Enter key(8 bytes): ";
    if(typeOs)
        wcin.ignore();
    getline(wcin, wskey);
    key = str2Hex(wstring_to_string(wskey));
    if(key.size() != 16)
        return 1;
    wcout << "8-bytes Key at hex: " << string_to_wstring(key) << endl;
    wcout<<"Enter initial vector(8 bytes): ";
    if(typeOs)
        wcin.ignore();
    getline(wcin, wsiv);
    iv = str2Hex(wstring_to_string(wsiv));
    if(iv.size() != 16)
        return 1;
    wcout << "8-bytes Initial vector at hex: " << string_to_wstring(iv) << endl;
    
    // Key Generation
    key = hex2bin(key);
    // getting 56 bit key from 64 bit using the parity bits
    key = permute(key, PC_1, 56); // key without parity
    // Splitting
    string left = key.substr(0, 28);
    string right = key.substr(28, 28);

    vector<string> rkb; // rkb for RoundKeys in binary
    vector<string> rk;  // rk for RoundKeys in hexadecimal
    for (int i = 0; i < 16; i++)
    {
        // Shifting
        left = shift_left(left, shiftTable[i]);
        right = shift_left(right, shiftTable[i]);
        // Combining
        string combine = left + right;
        // Key Compression
        string RoundKey = permute(combine, PC_2, 48);

        rkb.push_back(RoundKey);
        rk.push_back(bin2hex(RoundKey));
    }
    wcout  << "//////////////////////////////////////" << endl;
    wcout  << "Plain text: " << wsplain << endl;
    //encryptioin
    string cipher = encryptCBC(plain, iv, rkb, rk);
    wcout << "Cipher text: " << string_to_wstring(cipher) << endl;
    //decryption
    reverse(rkb.begin(), rkb.end());
    reverse(rk.begin(), rk.end());

    string text = decryptCBC(cipher, iv, rkb, rk);
    wcout << "Recovered text: "<< string_to_wstring(hex2String(text)) << endl;
}

string hex2bin(string s)
{
    // hexadecimal to binary conversion
    unordered_map<char, string> mp;
    mp['0'] = "0000";
    mp['1'] = "0001";
    mp['2'] = "0010";
    mp['3'] = "0011";
    mp['4'] = "0100";
    mp['5'] = "0101";
    mp['6'] = "0110";
    mp['7'] = "0111";
    mp['8'] = "1000";
    mp['9'] = "1001";
    mp['a'] = "1010";
    mp['b'] = "1011";
    mp['c'] = "1100";
    mp['d'] = "1101";
    mp['e'] = "1110";
    mp['f'] = "1111";
    string bin = "";
    for (long unsigned int i = 0; i < s.size(); i++)
    {
        bin += mp[s[i]];
    }
    return bin;
}
string bin2hex(string s)
{
    // binary to hexadecimal conversion
    unordered_map<string, string> mp;
    mp["0000"] = "0";
    mp["0001"] = "1";
    mp["0010"] = "2";
    mp["0011"] = "3";
    mp["0100"] = "4";
    mp["0101"] = "5";
    mp["0110"] = "6";
    mp["0111"] = "7";
    mp["1000"] = "8";
    mp["1001"] = "9";
    mp["1010"] = "a";
    mp["1011"] = "b";
    mp["1100"] = "c";
    mp["1101"] = "d";
    mp["1110"] = "e";
    mp["1111"] = "f";
    string hex = "";
    for (long unsigned int i = 0; i < s.length(); i += 4)
    {
        string ch = "";
        ch += s[i];
        ch += s[i + 1];
        ch += s[i + 2];
        ch += s[i + 3];
        hex += mp[ch];
    }
    return hex;
}
/////////////////////////
string str2Hex(string str)
{
    std::ostringstream os;
    for(unsigned char const& c : str)
    {
        os << std::hex << std::setprecision(2) << std::setw(2)
           << std::setfill('0') << static_cast<int>(c);
    }
    return os.str();
}
string hex2String(const std::string& input) 
{
    static const char* const lut = "0123456789abcdef";
    size_t len = input.length();
    if (len & 1) throw;
    std::string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        char a = input[i];
        const char* p = std::lower_bound(lut, lut + 16, a);
        if (*p != a) throw;
        char b = input[i + 1];
        const char* q = std::lower_bound(lut, lut + 16, b);
        if (*q != b) throw;
        output.push_back(((p - lut) << 4) | (q - lut));
    }
    return output;
}
/////////////////////////
string permute(string k, int *arr, int n)
{
    string per = "";
    for (int i = 0; i < n; i++)
    {
        per += k[arr[i] - 1];
    }
    return per;
}

string shift_left(string k, int shifts)
{
    string s = "";
    for (int i = 0; i < shifts; i++)
    {
        for (int j = 1; j < 28; j++)
        {
            s += k[j];
        }
        s += k[0];
        k = s;
        s = "";
    }
    return k;
}

string xor_(string a, string b)
{
    string ans = "";
    for (long unsigned int i = 0; i < a.size(); i++)
    {
        if (a[i] == b[i])
        {
            ans += "0";
        }
        else
        {
            ans += "1";
        }
    }
    return ans;
}
string encrypt(string pt, vector<string> rkb, vector<string> rk)
{
    // Initial Permutation
    pt = permute(pt, IP, 64);

    // Splitting
    string left = pt.substr(0, 32);
    string right = pt.substr(32, 32);

    for (int i = 0; i < 16; i++)
    {

        string right_expanded = permute(right, E, 48);
        // XOR RoundKey[i] and right_expanded
        string x = xor_(rkb[i], right_expanded);
        // S-boxes
        string op = "";
        for (int i = 0; i < 8; i++)
        {
            int row = 2 * int(x[i * 6] - '0') + int(x[i * 6 + 5] - '0');
            int col = 8 * int(x[i * 6 + 1] - '0') + 4 * int(x[i * 6 + 2] - '0') + 2 * int(x[i * 6 + 3] - '0') + int(x[i * 6 + 4] - '0');
            int val = S_BOX[i][row][col];
            op += char(val / 8 + '0');
            val = val % 8;
            op += char(val / 4 + '0');
            val = val % 4;
            op += char(val / 2 + '0');
            val = val % 2;
            op += char(val + '0');
        }
        // Straight D-box
        op = permute(op, P, 32);

        // XOR left and op
        x = xor_(op, left);
        left = x;

        // Swapper
        if (i != 15)
        {
            swap(left, right);
        }
    }
    // Combination
    string combine = left + right;
    // Final Permutation
    string cipher = permute(combine, IP_1, 64);
    return cipher;
}

string encryptCBC(string plain, string iv, vector<string> rkb, vector<string> rk)
{
    string cipher;
    int count = 0;
    int begin = 0;
    iv = hex2bin(iv);
    plain = hex2bin(plain);

    for (long unsigned int i = 0; i < plain.length(); i++)
    {
        count++;
        if (count % 64 == 0)
        {
            string hexTemp = plain.substr(begin, 64);
            string temp = xor_(hexTemp, iv);
            cipher += encrypt(temp, rkb, rk);
            iv = cipher;
            begin = i + 1;
        }
    }
    cipher = bin2hex(cipher);
    return cipher;
}

string decryptCBC(string cipher, string iv, vector<string> rkb, vector<string> rk)
{
    string recovered;
    int count = 0;
    int begin = 0;
    
    iv = hex2bin(iv);
    cipher = hex2bin(cipher);
    
    for (long unsigned int i = 0; i < cipher.length(); i++)
    {
        count++;
        if (count % 64 == 0)
        {
            string hexTemp = cipher.substr(begin, 64);
            string block = encrypt(hexTemp, rkb, rk);
            
            recovered += xor_(block, iv);
            iv = hexTemp;

            begin = i + 1;
        }
    }
    recovered = bin2hex(recovered);
    return recovered;
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