#include "stdafx.h"
#include "sha1.h"

SHA1::SHA1()
{}

BigInt SHA1::getDigest(std::vector<char>& data)
{
    size_t dataSizeBeforePreProcess = data.size();

    return BigInt();
}

void SHA1::preProcessData(std::vector<char>& data)
{
    data.push_back(0x80);   // Add 1 bit (actually 1 byte with the binary value 1000 0000) 

    // If data length % 512 is not equals 448 bits
    size_t dataModulus = data.size() % 64 != 56;
    if (dataModulus != 56) {
        data.resize(data.size() + 56 - dataModulus);
        // TODO: memset with 0
    }
}

void SHA1::processBlock(const std::vector<char>& data, size_t blockOffsetIndex)
{}
