#include "stdafx.h"
#include "rsa_digital_signature.h"

#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <fstream>

RSADigitalSignature::RSADigitalSignature() 
    : hashAlgorithm_(std::make_unique<SHA1>()), digest_(),
      digitalSignature_(),
      operationTime_()
{}

bool RSADigitalSignature::setupRsaParams(const BigInt& p, const BigInt& q, const BigInt& e)
{
    using namespace boost::multiprecision;

    const BigInt minModulus("0x80000000000000000000000000000000000000000");
    BigInt n = p * q;
    BigInt phi_n = (p - 1) * (q - 1);
    isEachParamCorrect_ = false;

    if (!miller_rabin_test(p, 25)) {
        error_ = Error::NotPrime_p;
        return false;
    }
    else if (!miller_rabin_test(q, 25)) {
        error_ = Error::NotPrime_q;
        return false;
    }
    else if (n < minModulus) {
        error_ = Error::TooLowModulus;
        return false;
    }
    else if (e <= 1LL || e >= phi_n) {
        error_ = Error::Incorrect_e;
        return false;
    }
    else if (gcd(e, phi_n) != 1LL) {
        error_ = Error::NotCoPrime_e;
        return false;
    }

    isEachParamCorrect_ = true;
    rsa_ = std::make_unique<RSA>(e, n, phi_n);

    return true;
}

bool RSADigitalSignature::signFile(std::filesystem::path filePath)
{
    using namespace std::chrono;
    
    uint64_t start, end;
    start = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();

    if (!isEachParamCorrect_) {
        return false;
    }

    uintmax_t originalFileSize = std::filesystem::file_size(filePath);
    std::vector<BYTE> fileData;
    if (!readFileData(fileData, filePath)) {
        error_ = Error::FileNotFound;
        return false;
    }

    digest_ = hashAlgorithm_->getDigest(fileData);
    createDigitalSignature();
    addDigitalSignatureToFile(originalFileSize, filePath);

    end = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    operationTime_ = end - start;

    return true;
}

bool RSADigitalSignature::checkDigitalSignature(std::filesystem::path filePath)
{
    using namespace std::chrono;

    uint64_t start, end;
    start = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();

    if (!isEachParamCorrect_) {
        return false;
    }

    getDigitalSignatureFromFile(filePath);
    BigInt digestFromSignature = getDigestFromDigitalSignature(digitalSignature_);

    std::vector<BYTE> fileData;
    uintmax_t fileDataSize = getFileDataSize(filePath);
    if (!readFileData(fileData, fileDataSize, filePath)) {
        error_ = Error::FileNotFound;
        return false;
    }

    digest_ = hashAlgorithm_->getDigest(fileData);
    bool result = digestFromSignature == digest_;

    end = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    operationTime_ = end - start;

    return result;
}

RSADigitalSignature::Error RSADigitalSignature::getLastError() const
{
    return error_;
}

const BigInt& RSADigitalSignature::getDigest() const
{
    return digest_;
}

std::string RSADigitalSignature::getDigestStr() const
{
    std::stringstream strStream;
    strStream << std::hex << digest_;

    return strStream.str();
}

const BigInt& RSADigitalSignature::getDigitalSignature() const
{
    return digitalSignature_;
}

std::string RSADigitalSignature::getDigitalSignatureStr() const
{
    std::stringstream strStream;
    strStream << std::hex << digitalSignature_;

    return strStream.str();
}

uint64_t RSADigitalSignature::getLastOperationTime() const
{
    return operationTime_;
}

bool RSADigitalSignature::readFileData(std::vector<BYTE>& container, std::filesystem::path filePath) const
{
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    uintmax_t fileSize = std::filesystem::file_size(filePath);

    container.clear();
    container.resize(fileSize);

    file >> std::noskipws;
    file.read(reinterpret_cast<char*>(container.data()), fileSize);

    return true;
}

bool RSADigitalSignature::readFileData(std::vector<BYTE>& container, uintmax_t dataSize, std::filesystem::path filePath) const
{
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    container.clear();
    container.resize(dataSize);

    file >> std::noskipws;
    file.read(reinterpret_cast<char*>(container.data()), dataSize);

    return true;
}

void RSADigitalSignature::createDigitalSignature()
{
    digitalSignature_ = RSA::decrypt(digest_, rsa_->getPrivateKey());
}

void RSADigitalSignature::addDigitalSignatureToFile(uintmax_t originalFileSize, std::filesystem::path filePath) const
{
    using namespace boost::archive;

    std::ofstream file(filePath, std::ios::binary | std::ios::app);
    binary_oarchive arch(file, archive_flags::no_header);
    
    arch << digitalSignature_;

    uintmax_t fileSizeWithSignature = file.tellp();
    uintmax_t signatureSize = fileSizeWithSignature - originalFileSize;
    arch << signatureSize;
}

uintmax_t RSADigitalSignature::getFileDataSize(std::filesystem::path signedFilePath) const
{
    std::ifstream file(signedFilePath, std::ios::binary);

    uintmax_t signatureSize = 0;
    file.seekg(-sizeof(signatureSize), std::ios::end);
    file.read(reinterpret_cast<char*>(&signatureSize), sizeof(signatureSize));

    return std::filesystem::file_size(signedFilePath) - signatureSize - sizeof(signatureSize);
}

void RSADigitalSignature::getDigitalSignatureFromFile(std::filesystem::path signedFilePath)
{
    using namespace boost::archive;

    std::ifstream file(signedFilePath, std::ios::binary);

    uintmax_t signatureSize = 0;
    file.seekg(-sizeof(signatureSize), std::ios::end);
    binary_iarchive arch(file, archive_flags::no_header);
    arch >> signatureSize;

    uintmax_t signatureOffset = std::filesystem::file_size(signedFilePath) - signatureSize - sizeof(signatureSize);
    file.seekg(signatureOffset);
    arch >> digitalSignature_;
}

BigInt RSADigitalSignature::getDigestFromDigitalSignature(const BigInt& digitalSignature) const
{
    return RSA::encrypt(digitalSignature, rsa_->getPublicKey());
}
