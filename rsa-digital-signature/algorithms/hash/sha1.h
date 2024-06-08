#pragma once

#include "hash_algorithm.h"

class SHA1 : public HashAlgorithm {
public:
    SHA1();

    virtual BigInt getDigest(std::vector<BYTE>& data) override;
    
private:
    void preProcessData(std::vector<BYTE>& data);
    void processBlock(const std::vector<BYTE>& data, size_t blockOffsetIndex);
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
};
