#pragma once

#include <boost/multiprecision/cpp_int.hpp>

using BigInt = boost::multiprecision::cpp_int;

class HashAlgorithm {
public:
    HashAlgorithm();

    virtual BigInt getDigest(std::vector<BYTE>& data) = 0;
    virtual const BigInt& getLastDigest() const;
    virtual std::string getLastDigestStr() const;

protected:
    BigInt digest_;
};
