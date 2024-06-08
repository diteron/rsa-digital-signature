#include "stdafx.h"
#include "hash_algorithm.h"

HashAlgorithm::HashAlgorithm()
    : digest_()
{}

const BigInt& HashAlgorithm::getLastDigest() const
{
    return digest_;
}

std::string HashAlgorithm::getLastDigestStr() const
{
    std::stringstream strStream;
    strStream << std::hex << digest_;

    return strStream.str();
}
