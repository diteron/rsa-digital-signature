#include "stdafx.h"
#include "rsa_digital_signature.h"

#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <fstream>

RSADigitalSignature::RSADigitalSignature() 
    : fileData_(), sha1_(), sha1Digest_(), sha1DigestStr_(),
      digitalSignature_(), digitalSignatureStr_()
{}

bool RSADigitalSignature::setupRsaParams(const BigInt& p, const BigInt& q, const BigInt& e)
{
    using namespace boost::multiprecision;

    const BigInt minModulus("0x8000000000000000000000000000000000000000");
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

    uintmax_t fileSize = std::filesystem::file_size(filePath);
    if (!readFileData(filePath, fileSize)) {
        error_ = Error::FileNotFound;
        return false;
    }

    sha1Digest_ = sha1_.getDigest(fileData_);
    sha1DigestStr_ = sha1_.getLastDigestStr();

    createDigitalSignature();
    addDigitalSignatureToFile(filePath, fileSize);

    return true;
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

bool RSADigitalSignature::readFileData(std::filesystem::path filePath, uintmax_t fileSize)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        error_ = Error::FileNotFound;
        return false;
    }

    file >> std::noskipws;
    fileData_.reserve(fileSize);
    fileData_.insert(fileData_.begin(),
                     std::istream_iterator<BYTE>(file),
                     std::istream_iterator<BYTE>());

    return true;
}

void RSADigitalSignature::createDigitalSignature()
{
    digitalSignature_ = RSA::decrypt(sha1Digest_, rsa_->getPrivateKey());
    
    std::stringstream strStream;
    strStream << std::hex << digitalSignature_;
    digitalSignatureStr_ = strStream.str();
}

void RSADigitalSignature::addDigitalSignatureToFile(std::filesystem::path filePath, uintmax_t fileSize) const
{
    using namespace boost::archive;

    std::ofstream file(filePath, std::ios::binary | std::ios::app);
    binary_oarchive arch(file, boost::archive::archive_flags::no_header);
    arch << digitalSignature_;
    arch << fileSize;
}
