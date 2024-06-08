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

    const BigInt& getDigest() const;
    std::string getDigestStr() const;
    const BigInt& getDigitalSignature() const;
    std::string getDigitalSignatureStr() const;
    uint64_t getLastOperationTime() const;

private:
    bool readFileData(std::vector<BYTE>& container, std::filesystem::path filePath) const;
    bool readFileData(std::vector<BYTE>& container, uintmax_t dataSize, std::filesystem::path filePath) const;
    void createDigitalSignature();
    void addDigitalSignatureToFile(std::filesystem::path filePath) const;
    void addDigitalSignatureSizeToFile(uintmax_t originalFileSize, std::filesystem::path filePath) const;

    uintmax_t getFileDataSize(std::filesystem::path signedFilePath) const;
    void getDigitalSignatureFromFile(std::filesystem::path signedFilePath);
    BigInt getDigestFromDigitalSignature(const BigInt& digitalSignature) const;

    Error error_ = Error::ParamsNotSetup;
    bool isEachParamCorrect_ = false;

    SHA1 sha1_;
    BigInt sha1Digest_;

    std::unique_ptr<RSA> rsa_ = nullptr;

    BigInt digitalSignature_;

    uint64_t operationTime_;
};
