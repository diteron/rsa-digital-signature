#pragma once

#include <boost/multiprecision/cpp_int.hpp>

using BigInt = boost::multiprecision::cpp_int;

class SHA1 {
public:
    SHA1();
    BigInt getDigest(std::vector<char> data);
    void processBlock(const std::vector<char>& data, size_t blockOffsetIndex);
    
private:
    void preProcessData(std::vector<char>& data);

    const int SHA1Size = 20;
    const int BlockSize = 64;

    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;


};

