#include "stdafx.h"
#include "sha1.h"

SHA1::SHA1() : digest_(), digestStr_()
{}

BigInt SHA1::getDigest(std::vector<unsigned char>& data)
{
    h0_ = 0x67452301;
    h1_ = 0xEFCDAB89;
    h2_ = 0x98BADCFE;
    h3_ = 0x10325476;
    h4_ = 0xC3D2E1F0;

    preProcessData(data);
    size_t currentOffset = 0;
    while (currentOffset < data.size()) {
        processBlock(data, currentOffset);
        currentOffset += BlockSize_;
    }

    digest_ = combineDigest();
    digestStr_ = createDigestStr();

    return digest_;
}

const BigInt& SHA1::getLastDigest() const
{
    return digest_;
}

const std::string& SHA1::getLastDigestStr() const
{
    return digestStr_;
}

void SHA1::preProcessData(std::vector<unsigned char>& data)
{
    size_t initialDataSize = data.size() * 8;   // In bits
   
    // Add 1 bit (actually 1 byte with the binary value 1000 0000) 
    data.push_back(0x80);   
    
    size_t dataModulus = data.size() % 64;
    while (dataModulus != 56) {
        data.push_back(0);
        dataModulus = data.size() % 64;
    }

    // Add initial message size as 64-bit big endian integer
    data.push_back(static_cast<unsigned char>(initialDataSize >> 56));
    data.push_back(static_cast<unsigned char>(initialDataSize >> 48));
    data.push_back(static_cast<unsigned char>(initialDataSize >> 40));
    data.push_back(static_cast<unsigned char>(initialDataSize >> 32));
    data.push_back(static_cast<unsigned char>(initialDataSize >> 24));
    data.push_back(static_cast<unsigned char>(initialDataSize >> 16));
    data.push_back(static_cast<unsigned char>(initialDataSize >> 8));
    data.push_back(static_cast<unsigned char>(initialDataSize));
}

void SHA1::processBlock(const std::vector<unsigned char>& data, size_t blockOffsetIndex)
{
    size_t t;
    uint32_t a = h0_;
    uint32_t b = h1_;
    uint32_t c = h2_;
    uint32_t d = h3_;
    uint32_t e = h4_;
    uint32_t K, f, W[80];

    // Create the sixteen 32-bit words and extend them into eighty 32-bit words
    for (t = 0; t < 16; ++t) {
        W[t] = (static_cast<unsigned char>(data[t * 4 + blockOffsetIndex])     << 24)
             | (static_cast<unsigned char>(data[t * 4 + 1 + blockOffsetIndex]) << 16)
             | (static_cast<unsigned char>(data[t * 4 + 2 + blockOffsetIndex]) << 8)
             |  static_cast<unsigned char>(data[t * 4 + 3 + blockOffsetIndex]);
    }
    for (; t < 80; ++t) {
        W[t] = cyclicLeftRotate(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    // Main loop
    uint32_t temp;
    for (t = 0; t < 80; ++t) {
        if (t < 20) {
            K = 0x5A827999;
            f = (b & c) | ((~b) & d);
        }
        else if (t < 40) {
            K = 0x6ED9EBA1;
            f = b ^ c ^ d;
        }
        else if (t < 60) {
            K = 0x8F1BBCDC;
            f = (b & c) | (b & d) | (c & d);
        }
        else {
            K = 0xCA62C1D6;
            f = b ^ c ^ d;
        }

        temp = cyclicLeftRotate(a, 5) + f + e + W[t] + K;
        e = d;
        d = c;
        c = cyclicLeftRotate(b, 30);
        b = a;
        a = temp;
    }

    h0_ += a;
    h1_ += b;
    h2_ += c;
    h3_ += d;
    h4_ += e;
}

uint32_t SHA1::cyclicLeftRotate(uint32_t data, uint32_t shiftBits) const
{
    return (data << shiftBits) | (data >> (32 - shiftBits));
}

uint32_t SHA1::convertToBigEndian(uint32_t num) const
{
    uint32_t b0 = (num & 0x000000FF) << 24;
    uint32_t b1 = (num & 0x0000FF00) << 8;
    uint32_t b2 = (num & 0x00FF0000) >> 8;
    uint32_t b3 = (num & 0xFF000000) >> 24;

    return b0 | b1 | b2 | b3;
}

BigInt SHA1::combineDigest() const 
{
    BigInt h0(convertToBigEndian(h0_));
    BigInt h1(convertToBigEndian(h1_));
    BigInt h2(convertToBigEndian(h2_));
    BigInt h3(convertToBigEndian(h3_));
    BigInt h4(convertToBigEndian(h4_));

    return BigInt((h0 << 128) | (h1 << 96)
                 | (h2 << 64) | (h3 << 32) | h4);
}

std::string SHA1::createDigestStr() const
{
    std::stringstream strStream;
    strStream << std::hex << h0_ << h1_ << h2_ << h3_ << h4_;
    return strStream.str();
}
