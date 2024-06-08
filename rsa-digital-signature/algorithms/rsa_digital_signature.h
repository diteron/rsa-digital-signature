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
    [[nodiscard]] bool checkDigitalSignature(std::filesystem::path filePath);
    Error getLastError() const;

    const std::string& getDigestStr() const;
    const std::string& getDigitalSignatureStr() const;
    uint64_t getLastOperationTime() const;

private:
    bool readFileData(std::filesystem::path filePath);
    void createDigitalSignature();
    void addDigitalSignatureToFile(std::filesystem::path filePath) const;
    void addDigitalSignatureSizeToFile(uintmax_t signatureSize, std::filesystem::path filePath) const;

    void getDigitalSignatureFromFile(std::filesystem::path filePath);
    BigInt getDigestFromDigitalSignature(const BigInt& digitalSignature) const;

    Error error_ = Error::ParamsNotSetup;
    bool isEachParamCorrect_ = false;

    std::vector<unsigned char> fileData_;
    uintmax_t fileSize_;

    SHA1 sha1_;
    BigInt sha1Digest_;
    std::string sha1DigestStr_;

    std::unique_ptr<RSA> rsa_ = nullptr;

    BigInt digitalSignature_;
    std::string digitalSignatureStr_;

    uint64_t operationTime_;
};
