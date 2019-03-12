package main

import (
	"fmt"

	kyber "go.dedis.ch/kyber"
	"go.dedis.ch/kyber/pairing/bn256"
	share "go.dedis.ch/kyber/share"
	bls "go.dedis.ch/kyber/sign/bls"
	tbls "go.dedis.ch/kyber/sign/tbls"
)

func main() {
	msg := []byte("Hello threshold Boneh-Lynn-Shacham yIFAN")
	suite := bn256.NewSuite()
	// This is a 3/5 threshold BLS
	n := 5
	t := n/2 + 1
	fmt.Printf("n = %v, t = %v\n\n", n, t)
	// we need 5 secrets
	var secrets [5]kyber.Scalar
	for i := 0; i < 5; i++ {
		// randomness for secret, we just need a scalar here, so it
		// does not matter using g1 or g2
		secrets[i] = suite.G1().Scalar().Pick(suite.RandomStream())
	}

	priPolyList := make([]*share.PriPoly, n)
	pubPolyList := make([]*share.PubPoly, n)
	priShares := make([][]*share.PriShare, n)
	pubShares := make([][]*share.PubShare, n)

	// create 5 pri and pub polys from its secret
	for index, secret := range secrets {
		priPoly := share.NewPriPoly(
			suite.G2(),
			t,
			secret,
			suite.RandomStream(),
		)

		pubPoly := priPoly.Commit(
			suite.G2().Point().Base(),
		)
		priPolyList[index] = priPoly
		pubPolyList[index] = pubPoly
		priShares[index] = priPoly.Shares(n)
		pubShares[index] = pubPoly.Shares(n)

	}

	// this is the recovered private share for the combine private poly for each node
	dkgShares := make([]*share.PriShare, n)
	for i := 0; i < n; i++ {
		acc := suite.G2().Scalar().Zero()
		for j := 0; j < n; j++ { // assuming all participants are in the qualified set
			acc = suite.G2().Scalar().Add(acc, priShares[j][i].V)
		}
		dkgShares[i] = &share.PriShare{i, acc}
	}

	// first recover the combined pub poly and then calculate
	// pub share for the combined pub poly for each node
	var pubPolyAll *share.PubPoly
	dkgPubShares := make([]*share.PubShare, n)
	// combine the pub poly
	pubPolyAll = pubPolyList[0]
	for i := 1; i < n; i++ {
		pubPolyAll, _ = pubPolyAll.Add(pubPolyList[i])
	}
	// calculate pub share for each node
	for i := 0; i < n; i++ {
		dkgPubShares[i] = pubPolyAll.Eval(i)
	}

	// verify public key and private key matches
	for i := 0; i < n; i++ {
		fmt.Printf(
			"%v\n%v\n\n",
			suite.G2().Point().Mul(dkgShares[i].V, nil),
			dkgPubShares[i].V,
		)
	}

	// now we have dkg pub & pri shares
	// lets get sig shares
	sigShares := make([][]byte, n)
	for i, x := range dkgShares {
		if sig, err := tbls.Sign(suite, x, msg); err == nil {
			sigShares[i] = sig
		} else {
			fmt.Printf("dkg sig failed, %v\n", err)
		}
	}

	// now we have everything: pri, pub and sig shares
	// we can recover the aggregated share and verify
	allSig, err := tbls.Recover(suite, pubPolyAll, msg, sigShares, t, n)
	fmt.Printf("%v, %v\n", allSig[:32], err)
	err = bls.Verify(suite, pubPolyAll.Commit(), msg, allSig)
	if err != nil {
		fmt.Printf("allsig verify failed, %v\n", err)
	} else {
		fmt.Printf("yeah!!!! %v\n", err)
	}
}
