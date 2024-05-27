#include "stdafx.h"
#include "rsa_digital_signature.h"

#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <fstream>

RSADigitalSignature::RSADigitalSignature() 
    : fileData_(), fileSize_(),
      sha1_(), sha1Digest_(), sha1DigestStr_(),
      digitalSignature_(), digitalSignatureStr_()
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
    if (!isEachParamCorrect_) {
        return false;
    }

    fileSize_ = std::filesystem::file_size(filePath);
    if (!readFileData(filePath)) {
        error_ = Error::FileNotFound;
        return false;
    }

    sha1Digest_ = sha1_.getDigest(fileData_);
    sha1DigestStr_ = sha1_.getLastDigestStr();

    createDigitalSignature();
    addDigitalSignatureToFile(filePath);

    return true;
}

bool RSADigitalSignature::checkDigitalSignature(std::filesystem::path filePath)
{
    if (!isEachParamCorrect_) {
        return false;
    }

    getDigitalSignatureFromFile(filePath);
    BigInt digestFromSignature = getDigestFromDigitalSignature(digitalSignature_);

    if (!readFileData(filePath)) {
        error_ = Error::FileNotFound;
        return false;
    }

    BigInt fileDigest = sha1_.getDigest(fileData_);

    return digestFromSignature == fileDigest;
}

RSADigitalSignature::Error RSADigitalSignature::getLastError() const
{
    return error_;
}

const std::string& RSADigitalSignature::getDigestStr() const
{
    return sha1DigestStr_;
}

const std::string& RSADigitalSignature::getDigitalSignatureStr() const
{
    return digitalSignatureStr_;
}

bool RSADigitalSignature::readFileData(std::filesystem::path filePath)
{
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        error_ = Error::FileNotFound;
        return false;
    }

    fileData_.clear();
    fileData_.resize(fileSize_);

    file >> std::noskipws;
    file.read(reinterpret_cast<char*>(fileData_.data()), fileSize_);

    return true;
}

void RSADigitalSignature::createDigitalSignature()
{
    digitalSignature_ = RSA::decrypt(sha1Digest_, rsa_->getPrivateKey());
    
    std::stringstream strStream;
    strStream << std::hex << digitalSignature_;
    digitalSignatureStr_ = strStream.str();
}

void RSADigitalSignature::addDigitalSignatureToFile(std::filesystem::path filePath) const
{
    using namespace boost::archive;

    std::ofstream file(filePath, std::ios::binary | std::ios::app);
    binary_oarchive arch(file, archive_flags::no_header);
    arch << digitalSignature_;
    arch << fileSize_;
}

void RSADigitalSignature::getDigitalSignatureFromFile(std::filesystem::path filePath)
{
    using namespace boost::archive;

    std::ifstream file(filePath, std::ios::binary);

    file.seekg(-8, std::ios::end);
    binary_iarchive arch(file, archive_flags::no_header);
    arch >> fileSize_;

    file.seekg(fileSize_);
    arch >> digitalSignature_;
}

BigInt RSADigitalSignature::getDigestFromDigitalSignature(const BigInt& digitalSignature) const
{
    return RSA::encrypt(digitalSignature, rsa_->getPublicKey());
}
