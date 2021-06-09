#include "StdAfx.h"

// Crypto++ Includes
#include "cryptlib.h"
#include "oids.h"
#include "osrng.h"
#include "eccrypto.h"
#include "asn.h"
#include "ecp.h"
#include "ec2n.h"
#include "simple.h"

// Crypto++ Library
#if defined(_MSC_VER)
# ifdef _DEBUG
#  pragma comment (lib, "cryptlibd")
# else
#  pragma comment (lib, "cryptlib")
# endif
#endif

#define ECC_ALGORITHM CryptoPP::ECP
// #define ECC_ALGORITHM CryptoPP::EC2N

// ECC Curves over F(p)
// Use when ECC_ALGORITHM is CryptoPP::ECP
//
// #define ECC_CURVE CryptoPP::ASN1::secp112r1()
// #define ECC_CURVE CryptoPP::ASN1::secp112r2()
// #define ECC_CURVE CryptoPP::ASN1::secp128r1()
// #define ECC_CURVE CryptoPP::ASN1::secp128r2()
// #define ECC_CURVE CryptoPP::ASN1::secp160r1()
// #define ECC_CURVE CryptoPP::ASN1::secp160k1()
// #define ECC_CURVE CryptoPP::ASN1::secp160r2()
#define ECC_CURVE CryptoPP::ASN1::brainpoolP160r1()
// #define ECC_CURVE CryptoPP::ASN1::secp192k1()
// #define ECC_CURVE CryptoPP::ASN1::ASN1::brainpoolP192r1()
// #define ECC_CURVE CryptoPP::ASN1::secp224k1()
// #define ECC_CURVE CryptoPP::ASN1::secp224r1()
// #define ECC_CURVE CryptoPP::ASN1::brainpoolP224r1()
// #define ECC_CURVE CryptoPP::ASN1::secp256k1()
// #define ECC_CURVE CryptoPP::ASN1::brainpoolP256r1()
// #define ECC_CURVE CryptoPP::ASN1::brainpoolP320r1()
// #define ECC_CURVE CryptoPP::ASN1::secp384r1()
// #define ECC_CURVE CryptoPP::ASN1::brainpoolP384r1()
// #define ECC_CURVE CryptoPP::ASN1::secp521r1()
// #define ECC_CURVE CryptoPP::ASN1::brainpoolP512r1()

// ECC Curves over GF(2)
// Use when ECC_ALGORITHM is CryptoPP::EC2N
//
// #define ECC_CURVE CryptoPP::ASN1::sect113r1()
// #define ECC_CURVE CryptoPP::ASN1::sect113r2()
// #define ECC_CURVE CryptoPP::ASN1::sect131r1()
// #define ECC_CURVE CryptoPP::ASN1::sect131r2()
// #define ECC_CURVE CryptoPP::ASN1::sect163k1()
// #define ECC_CURVE CryptoPP::ASN1::sect163r1()
// #define ECC_CURVE CryptoPP::ASN1::sect163r2()
// #define ECC_CURVE CryptoPP::ASN1::sect193r1()
// #define ECC_CURVE CryptoPP::ASN1::sect193r2()
// #define ECC_CURVE CryptoPP::ASN1::sect233k1()
// #define ECC_CURVE CryptoPP::ASN1::sect233r1()
// #define ECC_CURVE CryptoPP::ASN1::sect239k1()
// #define ECC_CURVE CryptoPP::ASN1::sect283k1()
// #define ECC_CURVE CryptoPP::ASN1::sect283r1()
// #define ECC_CURVE CryptoPP::ASN1::sect409k1()
// #define ECC_CURVE CryptoPP::ASN1::sect409r1()
// #define ECC_CURVE CryptoPP::ASN1::sect571k1()
// #define ECC_CURVE CryptoPP::ASN1::sect571r1()
  
int
main (int argc, char *argv[])
{
    
    try
    {    
        CryptoPP::ECIES < ECC_ALGORITHM >::PrivateKey privateKey;    
        CryptoPP::ECIES < ECC_ALGORITHM >::PublicKey publicKey;    
        CryptoPP::AutoSeededRandomPool rng;    

        // Key Generation
        privateKey.Initialize (rng, ECC_CURVE);    
        privateKey.MakePublicKey (publicKey);
    
        // Key Validation
        if (false == privateKey.Validate (rng, 3))
        {        
            throw runtime_error ("Private key validation failed");      
        }
    
        if (false == publicKey.Validate (rng, 3))
        {        
            throw runtime_error ("Public key validation failed");      
        }
    
        // Encryptor and Decryptor
        CryptoPP::ECIES < ECC_ALGORITHM >::Encryptor Encryptor (publicKey);    
        CryptoPP::ECIES < ECC_ALGORITHM >::Decryptor Decryptor (privateKey);
    
        // Message
        string plainText = "Yoda said, Do or do not. There is no try.";
	size_t plainTextLength = plainText.length () + 1;

        cout << "Plain text: " << plainText << endl;
        cout << "Plain text length is " << plainTextLength << " (including the trailing NULL)" << endl;

        // Size  
        size_t cipherTextLength = Encryptor.CiphertextLength (plainTextLength);
    
        if (0 == cipherTextLength)
        {        
            throw runtime_error ("cipherTextLength is not valid");      
        }
       
        cout << "Cipher text length is ";
        cout << cipherTextLength << endl;

        // Encryption buffer
        byte * cipherText = new byte[cipherTextLength];
        if (NULL == cipherText)
        {        
            throw runtime_error ("Cipher text allocation failure");      
        }
    
        memset (cipherText, 0xFB, cipherTextLength);

        // Encryption
        Encryptor.Encrypt (rng, reinterpret_cast < const byte * > (plainText.data ()), plainTextLength, cipherText); 

        // Size
        size_t recoveredTextLength = Decryptor.MaxPlaintextLength (cipherTextLength);    
        if (0 == recoveredTextLength)      
        {
            throw runtime_error ("recoveredTextLength is not valid");
        }

        // Decryption Buffer
        char * recoveredText = new char[recoveredTextLength];
        if (NULL == recoveredText)      
        {        
            throw runtime_error ("recoveredText allocation failure");      
        }    

        memset (recoveredText, 0xFB, recoveredTextLength);
    
        // Decryption
        Decryptor.Decrypt (rng, cipherText, cipherTextLength, reinterpret_cast < byte * >(recoveredText));     

        cout << "Recovered text: " << recoveredText << endl;
	cout << "Recovered text length is " << recoveredTextLength << endl;

        // Cleanup
        if (NULL != cipherText)
        {        
            delete[] cipherText;      
        }

        if (NULL != recoveredText)
        {        
            delete[] recoveredText;      
        }
    }
  
    catch (CryptoPP::Exception & e)
    {
        cerr << "Crypto++ error: " << e.what () << endl;
        return -3;
    }

    catch (runtime_error & e)
    {
        cerr << "Runtime error: " << e.what() << endl;
        return -2;
    }

    catch (exception & e)
    {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }

    return 0;
}

