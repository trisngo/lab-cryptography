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
        // oid standard curver
        CryptoPP::OID oid=ASN1::secp384r1();
        /* Create curve */ 
        CryptoPP::DL_GroupParameters_EC<ECP> curve384;
        curve384.Initialize(oid);
        /* Get curve paramaters p, a, b, G, n, h*/
        cout <<"Cofactor h="<< curve384.GetCofactor()<<endl;
        cout << "Subgroup Order n=" <<curve384.GetSubgroupOrder()<<endl;
        cout <<"Gx="<<curve384.GetSubgroupGenerator().x <<endl;
        cout <<"Gy="<<curve384.GetSubgroupGenerator().y<<endl;
        cout <<"Coefficient  a=" <<curve384.GetCurve().GetA()<<endl;
        cout <<"Coefficient  b=" <<curve384.GetCurve().GetB()<<endl;
        //cout <<"Prime number p=" <<curve384.GetCurve().GetField()<<endl;
        /* Computation on Curve Add, double, scalar mutiplication*/
        ECP::Point G=curve384.GetSubgroupGenerator();
        ECP::Point Q=curve384.GetCurve().Double(G); // G+G;
        cout << "Qx=" << Q.x << endl;
        cout << "Qy=" << Q.y << endl;
        Integer r("3451");
        cout << "number r=" << r<<endl;
        ECP::Point H=curve384.GetCurve().ScalarMultiply(G,r); // rP;
        cout << "Hx=" << H.x << endl;
        cout << "Hy=" << H.y << endl;
        ECP::Point I=curve384.GetCurve().Add(Q,H); // Q+H=2G+3451G
        cout << "Ix=" << I.x << endl;
        cout << "Iy=" << I.y << endl;
        // Verify
        Integer r1("3453");
        cout << "number r1=" << r1 <<endl;
        ECP::Point I1=curve384.GetCurve().ScalarMultiply(G,r1); // r1.G;
        cout << "I1x=" << I1.x << endl;
        cout << "I1y=" << I1.y << endl;
        cout << curve384.GetCurve().Equal(I,I1) <<endl;
    }
