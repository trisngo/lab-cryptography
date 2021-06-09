//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/

/* Source, Sink */
#include "include/cryptopp/filters.h"

#include <ctime>
#include <iostream>
#include <string>
using namespace std;

/* Randomly generator*/
#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Integer arithmatics*/
#include "include/cryptopp/integer.h"
using CryptoPP::Integer;
#include "include/cryptopp/nbtheory.h"
using CryptoPP::ModularSquareRoot;

#include "include/cryptopp/ecp.h"
#include "include/cryptopp/eccrypto.h"
using CryptoPP::ECP;    // Prime field p
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include "include/cryptopp/pubkey.h"
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

/* standard curves*/
#include "include/cryptopp/asn.h"
#include "include/cryptopp/oids.h" // 
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;


int main(int argc, char* argv[])
{
    AutoSeededRandomPool rng;
// Contruct  ECP(const Integer &modulus, const FieldElement &A, const FieldElement &B);

        // User Defined Domain Parameters for curve y^2 =x^3 + ax +b
        // Modulus p
        Integer p("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffh");
        // Coefiction a
        Integer a("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffch");
        // Coefiction b
        Integer b("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefh");

        /* ECC curve */
        CryptoPP::ECP eqcurve384(p, a, b); // buide curve y^2 =x^3 +ax +b
        /* subgroup <G> on curve */ 
         // x, y: Base Point G
        Integer x("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7h");
        Integer y("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fh");
        // Creat point G
        ECP::Point G(x,y);
        // Oder n of group <G>
        Integer n("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973h");
        //Cofactors
         Integer h("01h");
        /* Set ECC parameters and subgroup <G>*/
        // CryptoPP::DL_GroupParameters_EC<ECP> curve256(eqcurve256,G,n,h);
        CryptoPP::DL_GroupParameters_EC<ECP> curve384;
        curve384.Initialize(eqcurve384,G,n,h);
        /* Get curve paramaters p, a, b, G, n, h*/
        cout <<"Prime number p="<< curve384.GetCurve().GetField().GetModulus()<<endl;
        cout <<"Coefficient  a=" <<curve384.GetCurve().GetA()<<endl;
        cout <<"Coefficient  b=" <<curve384.GetCurve().GetB()<<endl;
        cout <<"Gx="<<curve384.GetSubgroupGenerator().x <<endl;
        cout <<"Gy="<<curve384.GetSubgroupGenerator().y<<endl;
        cout << "Subgroup Order n=" <<curve384.GetSubgroupOrder()<<endl;
        cout <<"Cofactor h="<< curve384.GetCofactor()<<endl;

        /* Computation on Curve Add, double, scalar mutiplication*/
        ECP::Point Q=curve384.GetCurve().Add(G,G); // G+G; // check Double?
        cout << "Qx=" << Q.x << endl;
        cout << "Qy=" << Q.y << endl;
        Integer r("3451");
        r%=p;
        cout << "number r=" << r<<endl;
        ECP::Point H=curve384.GetCurve().ScalarMultiply(G,r); // rP;
        cout << "Hx=" << H.x << endl;
        cout << "Hy=" << H.y << endl;
        ECP::Point I=curve384.GetCurve().Add(Q,H); // Q+H=2G+3451G
        cout << "Ix=" << I.x << endl;
        cout << "Iy=" << I.y << endl;
        // Verify
        Integer r1("3453");
        r1%=p;
        cout << "number r1=" << r1 <<endl;
        ECP::Point I1=curve384.GetCurve().ScalarMultiply(G,r1); // r1.G;
        cout << "I1x=" << I1.x << endl;
        cout << "I1y=" << I1.y << endl;
        cout << curve384.GetCurve().Equal(I,I1) <<endl;
    }