#pragma once

#include "sha1.h"
#include "rsa.h"

class RSADigitalSignature {
public:
    RSADigitalSignature();

    enum Error {
        ParamsNotSetup,
        NotPrime_p,
        NotPrime_q,
        TooLowModulus,
        Incorrect_e,
        NotCoPrime_e,
        FileNotFound
    };

    [[nodiscard]] bool setupRsaParams(const BigInt& p, const BigInt& q, const BigInt& e = 65537LL);
    [[nodiscard]] bool signFile(std::filesystem::path filePath);
    Error getLastError() const;

    const std::string& getDigestStr() const;
    const std::string& getDigitalSignatureStr() const;

private:
    bool readFileData(std::filesystem::path filePath, uintmax_t fileSize);
    void createDigitalSignature();
    void addDigitalSignatureToFile(std::filesystem::path filePath, uintmax_t fileSize) const;

    Error error_ = Error::ParamsNotSetup;
    bool isEachParamCorrect_ = false;

    std::vector<unsigned char> fileData_;
    SHA1 sha1_;
    BigInt sha1Digest_;
    std::string sha1DigestStr_;

    std::unique_ptr<RSA> rsa_ = nullptr;
    BigInt digitalSignature_;
    std::string digitalSignatureStr_;
   
};

