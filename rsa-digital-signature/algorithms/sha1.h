#pragma once

#include <boost/multiprecision/cpp_int.hpp>

using BigInt = boost::multiprecision::cpp_int;

class SHA1 {
public:
    SHA1();

    BigInt getDigest(std::vector<unsigned char>& data);
    const BigInt& getLastDigest() const;
    const std::string& getLastDigestStr() const;
    
private:
    void preProcessData(std::vector<unsigned char>& data);
    void processBlock(const std::vector<unsigned char>& data, size_t blockOffsetIndex);
    uint32_t cyclicLeftRotate(uint32_t data, uint32_t shiftBits) const;
    uint32_t convertToBigEndian(uint32_t num) const;
    BigInt combineDigest() const;
    std::string createDigestStr() const;

    const int BlockSize_ = 64;      // In bytes

    uint32_t h0_ = 0x67452301;
    uint32_t h1_ = 0xEFCDAB89;
    uint32_t h2_ = 0x98BADCFE;
    uint32_t h3_ = 0x10325476;
    uint32_t h4_ = 0xC3D2E1F0;

    BigInt digest_;
    std::string digestStr_;
};
