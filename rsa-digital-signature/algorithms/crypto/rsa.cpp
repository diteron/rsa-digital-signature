#include "stdafx.h"
#include "rsa.h"

RSA::RSA(const BigInt& e, const BigInt& n, const BigInt& phi_n)
    : e_(e), n_(n), phi_n_(phi_n),
      d_(), privateKey_(), publicKey_()
{
    BigInt x, y;
    BigInt gcd = gcde(e_, phi_n_, &x, &y);

    d_ = x > 0 ? x : x + phi_n_;

    privateKey_ = PrivateKey{d_, n_};
    publicKey_ = PublicKey{e_, n_};
}

RSA::PrivateKey RSA::getPrivateKey() const
{
    return privateKey_;
}

RSA::PublicKey RSA::getPublicKey() const
{
    return publicKey_;
}

BigInt RSA::encrypt(const BigInt& m, const PublicKey& publicKey)
{
    return boost::multiprecision::powm(m, publicKey.e, publicKey.n);
}

BigInt RSA::decrypt(const BigInt& c, const PrivateKey& privateKey)
{
    return boost::multiprecision::powm(c, privateKey.d, privateKey.n);
}

BigInt RSA::gcde(BigInt a, BigInt b, BigInt* x, BigInt* y) const
{
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }

    BigInt x1, y1;
    BigInt gcd = gcde(b % a, a, &x1, &y1);
    *x = y1 - (b / a) * x1;
    *y = x1;
    return gcd;
}
