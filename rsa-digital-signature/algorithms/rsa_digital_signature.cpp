#include "stdafx.h"
#include "rsa_digital_signature.h"

#include <boost/multiprecision/miller_rabin.hpp>

RSADigitalSignature::RSADigitalSignature()
{}

bool RSADigitalSignature::setupRsaParams(const BigInt& p, const BigInt& q, const BigInt& e)
{
    using namespace boost::multiprecision;

    const BigInt minModulus("0x8000000000000000000000000000000000000000");  // Check if it's actually hex
    BigInt n = p * q;
    BigInt phiN = (p - 1) * (q - 1);

    if (!miller_rabin_test(p, 25)) {
        rsaError = RSAerror::NotPrime_p;
        return false;
    }
    else if (!miller_rabin_test(q, 25)) {
        rsaError = RSAerror::NotPrime_q;
        return false;
    }
    else if (n < minModulus) {
        rsaError = RSAerror::TooLowModulus;
        return false;
    }
    else if (e <= 1LL || e >= phiN) {
        rsaError = RSAerror::Incorrect_e;
        return false;
    }
    else if (gcd(e, phiN) != 1LL) {
        rsaError = RSAerror::NotCoPrime_e;
        return false;
    }

    // TODO: Add RSA class object creation

    return true;
}
