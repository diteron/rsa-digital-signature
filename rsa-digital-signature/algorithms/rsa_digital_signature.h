#pragma once

#include "sha1.h"

class RSADigitalSignature {
public:
    RSADigitalSignature();
    [[nodiscard]] bool setupRsaParams(const BigInt& p, const BigInt& q, const BigInt& e = 65537LL);

    enum RSAerror {
        Success,
        ParamsNotSetup,
        NotPrime_p,
        NotPrime_q,
        TooLowModulus,
        Incorrect_e,
        NotCoPrime_e
    };

private:
    RSAerror rsaError = RSAerror::ParamsNotSetup;
    
    SHA1 sha1;
   
};

