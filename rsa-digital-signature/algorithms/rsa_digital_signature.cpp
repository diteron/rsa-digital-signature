#include "stdafx.h"
#include "rsa_digital_signature.h"

#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/math/common_factor.hpp>

RSADigitalSignature::RSADigitalSignature()
{}

bool RSADigitalSignature::setupRsaParams(BigInt p, BigInt q, BigInt e)
{
    using namespace boost::multiprecision;

    if (!miller_rabin_test(p, 25)) {
        rsaError = RSAerror::NotPrime_p;
        return false;
    }
    else if (!miller_rabin_test(q, 25)) {
        rsaError = RSAerror::NotPrime_q;
        return false;
    }
    
    BigInt n = p * q;
    BigInt phiN = (p - 1) * (q - 1);
    if (e <= 1LL || e >= phiN) {
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
