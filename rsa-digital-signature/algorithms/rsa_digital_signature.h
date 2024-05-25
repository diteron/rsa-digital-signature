#pragma once

#include "sha1.h"

class RSADigitalSignature {
public:
    RSADigitalSignature();
    [[nodiscard]] bool setupRsaParams(BigInt p, BigInt q, BigInt e = 65537LL);

    enum RSAerror {
        Success,
        ParamsNotSetup,
        NotPrime_p,
        NotPrime_q,
        Incorrect_e,
        NotCoPrime_e
    };

private:
    RSAerror rsaError = RSAerror::ParamsNotSetup;
    
    SHA1 sha1;
   
};

