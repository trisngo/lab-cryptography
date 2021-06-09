// DPVal.cpp : Defines the entry point for the console application.

// Runtime Includes
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <stdexcept>
using std::runtime_error;

// Crypto++ Includes
#include "include/cryptopp/cryptlib.h"
#include "include/cryptopp/osrng.h"      // Random Number Generator
#include "include/cryptopp/eccrypto.h"   // Elliptic Curve
#include "include/cryptopp/ecp.h"        // F(p) EC
#include "include/cryptopp/integer.h"    // Integer Operations
#include "include/cryptopp/nbtheory.h"   // VerifyPrime, ModularRoot,
                        //   and ModularExponentiation

using CryptoPP::Integer;
using CryptoPP::AutoSeededRandomPool;

// Solves y^2 === x^3 + a*x + b (mod p)
Integer Solve(Integer x, Integer a, Integer b, Integer p);

// Returns 4*a^3 + 27*b^2 (mod p) (Discriminant)
Integer Disc(Integer a, Integer b, Integer p);

void Validate(Integer p, Integer a, Integer b,
               Integer x, Integer y,
               Integer n, Integer k);
// Debug
void DumpPublicKey(const CryptoPP::ECIES< CryptoPP::ECP >::PublicKey&  publicKey);
void DumpPrivateKey(const CryptoPP::ECIES< CryptoPP::ECP >::PrivateKey&  privateKey);

int main(int argc, char* argv[])
{
    AutoSeededRandomPool rng;

    try {

        // User Defined Domain Parameters
        //    This is Curve P-112 from NIST
        Integer p("6277101735386680763835789423207666416083908700390324961279");

        // a: fixed to speed underlying operations
        Integer a("-3");
        // b: satisfies b^2 * c === -27 (mod p)
        Integer b("0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1");

        // Cofactor (f) and Order (r)
        Integer f = 1;
        Integer r("6277101735386680763835789423176059013767194773182842284081");

        // n: n = f * r
        Integer n = f * r;

        // s: Input seed to SHA-1 algorithm
        //    Not used (included for completeness)
        Integer s("0x3045ae6fc8422f64ed579528d38120eae12196d5");
        // c: Output of SHA-1 Algorithm
        //    Not used (included for completeness)
        Integer c("0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65");

        // x, y: Base Point G
        Integer x("0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012");
        Integer y("0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811");

        //Interval [0, p-1]
        a %= p;     b %= p;     x %= p;     y %= p;

        CryptoPP::ECP ec(p, a, b);

        //   From cryptlib.h, Validate(...):
        //
        //   0 - using this object won't cause a crash or exception (rng is ignored)
        //   1 - this object will probably function (encrypt, sign, etc.) correctly
        //       (but may not check for weak keys and such)
        //   2 - make sure this object will function correctly, and do reasonable
        //       security checks
        //   3 - do checks that may take a long time
        if(false == ec.ValidateParameters(rng, 3))
        {
            throw runtime_error("EC parameter validation failure");
        }

        CryptoPP::ECIES< CryptoPP::ECP >::PrivateKey    privateKey;
        CryptoPP::ECIES< CryptoPP::ECP >::PublicKey     publicKey;

        // Curve Initialization and Key Generation        
        privateKey.Initialize(ec, CryptoPP::ECP::Point(x, y), n, f);
        privateKey.MakePublicKey(publicKey);

        if(false == privateKey.Validate(rng, 3))
        {           
            throw runtime_error("Private key validation failure");        
        }

        if(false == publicKey.Validate(rng, 3))
        {           
            throw runtime_error("Public key validation failure");
        }

        cout << "NIST P192 Curve Parameters:" << endl;
        cout << std::hex << "  p: " << p << endl;
        cout << std::hex << "  a: " << a << endl;
        cout << std::hex << "  b: " << b << endl;

        cout << std::dec << "  x: " << x << endl;
        cout << std::dec << "  y: " << y << endl;

        cout << std::dec << "  n: " << n << endl;
        cout << std::dec << "  f: " << f << endl;

        cout << endl;

        // a%p in case a<0.
        Validate(p, a, b, x, y, n, f);
    }

    catch(const CryptoPP::Exception& e)
    {
        cerr << "Error: " << e.what() << endl;
    }

    catch(const std::runtime_error& e)
    {
        cerr << "Error: " << e.what() << endl;
    }

    return 0;
}

void DumpPublicKey(const CryptoPP::ECIES< CryptoPP::ECP >::PublicKey&  publicKey)
{
    cout << "Public Key:" << endl;

    Integer p = publicKey.GetGroupParameters().GetCurve().FieldSize();
    cout << "  EC Parameter p: " << p << endl;

    Integer a = publicKey.GetGroupParameters().GetCurve().GetA();
    cout << "  EC Parameter a: " << a << endl;
    
    Integer b = publicKey.GetGroupParameters().GetCurve().GetB();
    cout << "  EC Parameter b: " << b << endl;

    Integer x = publicKey.GetGroupParameters().GetSubgroupGenerator().x;
    cout << "    Base Point x: " << x << endl;
    
    Integer y = publicKey.GetGroupParameters().GetSubgroupGenerator().y;
    cout << "    Base Point y: " << y << endl;
}

void DumpPrivateKey(const CryptoPP::ECIES< CryptoPP::ECP >::PrivateKey& privateKey)
{
    cout << "Private Key:" << endl;

    Integer x = privateKey.GetGroupParameters().GetSubgroupGenerator().x;
    cout << "       Base Point x: " << x << endl;
    
    Integer y = privateKey.GetGroupParameters().GetSubgroupGenerator().y;
    cout << "       Base Point y: " << y << endl;

    Integer r = privateKey.GetGroupParameters().GetGroupOrder();
    cout << "      Group Order r: " << r << endl;

    Integer n = privateKey.GetGroupParameters().GetSubgroupOrder();
    cout << "  Sub Group Order n: " << n << endl;

    Integer k = privateKey.GetGroupParameters().GetCofactor();
    cout << "         Cofactor k: " << k << endl;

    Integer m = privateKey.GetAbstractGroupParameters().GetMaxExponent();
    cout << "     Max Exponent m: " << m << endl;

    Integer e = privateKey.GetPrivateExponent();
    cout << "      Private Exp e: " << e << endl;
}

// Standards for Efficient Cryptography
// SEC 1: Elliptic Curve Cryptography
//   Elliptic Curve Domain Parameters over GF(p) Validation, pp 17-18
void Validate(Integer p, Integer a, Integer b,
               Integer x, Integer y,
               Integer n, Integer h)
{

    Integer t;    // scratch
    AutoSeededRandomPool rng;

    // SEC1, Section 3.1.1.2.1, page 18
    //   Check 1: p is an odd prime...
    if(true == CryptoPP::VerifyPrime(rng, p, 6))
    {
        cout << "p appears to be prime... OK" << endl;
    }            
    else
    {
        cout << "** p is composite **" << endl;
    }

    // SEC1, Section 3.1.1.2.1, page 18
    //   Check 1: [p] ... such that t = { 56, 64, ..., 192, 256 }
    // This needs to be tightened...
    if(p.BitCount() / 2 >= 56)
    {
        // cout << "t = { 56, 64, 80, 96, 112, 128, 192, 256}... OK" << endl;
    }
    else
    {
        cout << "** Security Level t may be too small **" << endl;
    }

    // SEC1, Section 3.1.1.2.1, page 18
    //   Check 2: a, b, g_x, g_y = [0, p-1]
    t = p - 1;
    if(a >= 0 && a <= t)
    {
        cout << "a is in the interval [0, p-1]... OK" << endl;
    }
    else
    {
        cout << "** a is not in the interval [0, p-1] **" << endl;
        cout << "   a: " << a << endl;
    }

    if(b >= 0 && b <= t)
    {
        cout << "b is in the interval [0, p-1]... OK" << endl;
    }
    else
    {
        cout << "** b is not in the interval [0, p-1] **" << endl;
        cout << "   b: " << b << endl;
    }

    if(x >= 0 && x <= t)
    {
        cout << "x is in the interval [0, p-1]... OK" << endl;
    }
    else
    {
        cout << "** x is not in the interval [0, p-1] **" << endl;
        cout << "   x: " << x << endl;
    }

    if(y >= 0 && y <= t)
    {
        cout << "y is in the interval [0, p-1]... OK" << endl;
    }
    else
    {
        cout << "** y is not in the interval [0, p-1] **" << endl;
        cout << "   y: " << y << endl;
    }

    // SEC1, Section 3.1.1.2.1, page 18
    //   Check 3: 4*a^3 + 27*b^2 != 0 (mod p)
    t = Disc(a, b, p);
    if(0 != t)
    {
        cout << "Discriminant != 0 (mod p)... OK" << endl;
    }            
    else
    {
        cout << "** Discriminant == 0 (mod p) **" << endl;
    }

    // SEC1, Section 3.1.1.2.1, page 18
    //   Check 4: y^2 == x^3 + a*x + b (mod p)
    t = Solve(x, a, b, p);
    if(y % p == t % p)
    {
        cout << "Base Point G(x,y) is on E(GF(p))... OK" << endl;
    }            
    else
    {
        cout << "** Base Point G(x,y) is not on E(GF(p)) **" << endl;
    }

    // SEC1, Section 3.1.1.2.1, page 18
    //   Check 5: n is an odd prime...
    if(true == CryptoPP::VerifyPrime(rng, n, 6))
    {
        cout << "n appears to be prime... OK" << endl;
    }            
    else
    {
        cout << "** n is composite **" << endl;
    }

    // SEC1, Section 3.1.1.2.1, page 18
    //   Check 6: h <= 4 ...
    if(h <= 4)
    {
        cout << "h <= 4... OK" << endl;
    }            
    else
    {
        cout << "** h is too large **" << endl;
    }

    // SEC1, Section 3.1.1.2.1, page 18
    //   Check 6: ... h = FLOOR((SQRT(P)+1)^2 / n)
    t = p.SquareRoot() + 1;
    t = t.Squared() / n;
    if(h == t)
    {
        cout << "h = FLOOR((SQRT(p)+1)^2 / n)... OK" << endl;
    }            
    else
    {
        cout << "** h != FLOOR((SQRT(p)+1)^2 / n) **" << endl;
    }

    // SEC1, Section 3.1.1.2.1, page 18
    //   Check 7: n*G = O (O is Point of Infinity)
    CryptoPP::ECP ec(p, a, b);
    if(ec.Identity() == ec.ScalarMultiply(CryptoPP::ECPPoint(x, y), n))
    {
        cout << "nG = O... OK" << endl;
    }
    else
    {
        cout << "** nG != O **" << endl;
    }

    // SEC1, Section 3.1.1.2.1, page 18
    //   Check 8: q^B != 1 (mod n) for any 1 <= B < 20 ...
    bool bResult = true;
    unsigned int B = 0;
    for(B = 1; B < 20 && true == bResult; B++)
    {
        bResult |= (1 != a_exp_b_mod_c(p, B, p));
    }
    if(true == bResult)
    {
        cout << "p^B != 1 (mod n) for any 1 <= B < 20... OK" << endl;
    }            
    else
    {
        cout << "** p^B = 1 (mod n) for B = " << --B << " **" << endl;
    }

    // SEC1, Section 3.1.1.2.1, page 18
    //   Check 8: ... n*h != p
    if(p != n * h)
    {
        cout << "n*h != p... OK" << endl;
    }            
    else
    {
        cout << "** n*h = p **" << endl;
    }
}

// Solves y^2 === x^3 + a*x + b (mod p)
Integer Solve(Integer x, Integer a, Integer b, Integer p)
{
    x %= p; a %= p; b %= p;

    Integer y = a_exp_b_mod_c(x, 3, p);
    y += a * x + b;
    return CryptoPP::ModularSquareRoot(y % p, p);
}

// Returns 4*a^3 + 27*b^2 (mod p) (Discriminant)
Integer Disc(Integer a, Integer b, Integer p)
{
    Integer d = 4 * a_exp_b_mod_c(a, 3, p);
    d += 27 * b.Squared();

    return d % p;
}
