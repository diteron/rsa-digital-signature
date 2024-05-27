#pragma once

#include <boost/multiprecision/cpp_int.hpp>

using BigInt = boost::multiprecision::cpp_int;

class RSA {
public:
    RSA() = delete;
    RSA(const BigInt& e, const BigInt& n, const BigInt& phi_n);

    struct PrivateKey {
        BigInt d;
        BigInt n;
    };

    struct PublicKey {
        BigInt e;
        BigInt n;
    };

    PrivateKey getPrivateKey() const;
    PublicKey getPublicKey() const;

    static BigInt encrypt(const BigInt& m, const PublicKey& privateKey);
    static BigInt decrypt(const BigInt& c, const PrivateKey& publicKey);

private:
    // Extended Euclidean algorithm
    BigInt gcde(BigInt a, BigInt b,
                BigInt* x, BigInt* y) const;

    BigInt e_;
    BigInt n_;
    BigInt phi_n_;
    BigInt d_;

    PrivateKey privateKey_;
    PublicKey publicKey_;
};

