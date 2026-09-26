package main

import (
	"crypto/rsa"
	"math/big"

	"github.com/cloudflare/circl/blindsign/blindrsa" // EXPECT:raw-rsa-blind-signature-library
)

func positive(priv *rsa.PrivateKey, x *big.Int) *big.Int {
	a := new(big.Int).Exp(x, priv.D, priv.N) // EXPECT:raw-rsa-go-bigint-private-exponent
	b := new(big.Int).Exp(x, priv.D, priv.PublicKey.N) // EXPECT:raw-rsa-go-bigint-private-exponent
	_ = blindrsa.SHA384PSSDeterministic // EXPECT:raw-rsa-blind-signature-library
	return a.Add(a, b)
}

func negative(pub *rsa.PublicKey, x *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	return new(big.Int).Exp(x, e, pub.N)
}
