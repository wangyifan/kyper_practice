package main

import (
	"fmt"

	kyber "go.dedis.ch/kyber/v3"
	share "go.dedis.ch/kyber/v3/share"
	bls "go.dedis.ch/kyber/v3/sign/bls"
	tbls "go.dedis.ch/kyber/v3/sign/tbls"
	random "go.dedis.ch/kyber/v3/util/random"

	geth12381 "github.com/ethereum/go-ethereum/crypto/bls12381"
	kilic12381 "github.com/kilic/bls12-381"
	kyber12381 "go.dedis.ch/kyber/v3/pairing/bls12381"
)

func bls_test1() {
	msg := []byte("Hello World")
	suite := kyber12381.NewSuite()
	// This is a T out of N threshold BLS
	n := 3
	t := 3
	fmt.Printf("n = %v, t = %v\n\n", n, t)
	// we need 5 secrets
	secrets := make([]kyber.Scalar, n)
	for i := 0; i < n; i++ {
		// randomness for secret, we just need a scalar here, so it
		// does not matter using g1 or g2
		secrets[i] = suite.G1().Scalar().Pick(suite.RandomStream())
	}

	priPolyList := make([]*share.PriPoly, n)
	pubPolyList := make([]*share.PubPoly, n)
	priShares := make([][]*share.PriShare, n)
	pubShares := make([][]*share.PubShare, n)

	// # 1 create 3 pri and pub polys from its secret
	for index, secret := range secrets {
		priPoly := share.NewPriPoly(
			suite.G2(),
			t,
			secret,
			suite.RandomStream(),
		)

		fmt.Printf("Polynomial #%d:\n", index+1)
		for i, coeff := range priPoly.Coefficients() {
			fmt.Printf("a%d = %v\n", i, coeff)
		}
		fmt.Printf("\n")

		pubPoly := priPoly.Commit(
			suite.G2().Point().Base(),
		)
		priPolyList[index] = priPoly
		pubPolyList[index] = pubPoly
		priShares[index] = priPoly.Shares(n)
		pubShares[index] = pubPoly.Shares(n)
	}

	// # 2 print all 3x3=9 private shares
	for i, shares := range priShares {
		fmt.Printf("Private Share #%d:\n", i+1)
		for _, share := range shares {
			fmt.Printf("Private[%d,%d]: %v\n", i+1, share.I+1, share.V)
		}
		fmt.Printf("\n")
	}

	fmt.Printf("\n")

	// # 3 print all 3x3 public shares
	for i, shares := range pubShares {
		fmt.Printf("Public Share #%d:\n", i+1)
		for _, share := range shares {
			fmt.Printf("Public[%d,%d]: %v\n", i+1, share.I+1, share.V)
		}
		fmt.Printf("\n")
	}

	fmt.Printf("\n\n")

	// # 4 combined private share for each node
	dkgShares := make([]*share.PriShare, n)
	for i := 0; i < n; i++ {
		acc := suite.G2().Scalar().Zero()
		fmt.Printf("Local Private Key #%d: ", i+1)
		for j := 0; j < n; j++ { // assuming all participants are in the qualified set
			acc = suite.G2().Scalar().Add(acc, priShares[j][i].V)
		}
		dkgShares[i] = &share.PriShare{i, acc}
		fmt.Printf("%v\n", dkgShares[i].V)
	}

	fmt.Printf("\n")

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
		fmt.Printf("Local Public Key #%d: ", i+1)
		dkgPubShares[i] = pubPolyAll.Eval(i)
		fmt.Printf("%v\n", dkgPubShares[i].V)
	}

	fmt.Printf("\n---------------------------------------------------------\n")
	fmt.Printf("\n---------------------------------------------------------\n")

	// # 5 signature share
	sigShares := make([][]byte, n)
	for i, pri := range dkgShares {
		if sig, err := tbls.Sign(suite, pri, msg); err == nil {
			sigShares[i] = sig
			fmt.Printf("Signature Share #%d: %x\n", i+1, sig)
		} else {
			fmt.Printf("dkg sig failed, %v\n", err)
		}
	}
	fmt.Printf("\n")
	fmt.Printf("Group Public Key: %v", pubPolyAll.Commit())
	fmt.Printf("\n")
	allSig, _ := tbls.Recover(suite, pubPolyAll, msg, sigShares, t, n)
	fmt.Printf("\n")
	fmt.Printf("Group Signature 1: %x\n", allSig)
	fmt.Printf("\n")
	err := bls.Verify(suite, pubPolyAll.Commit(), msg, allSig)
	fmt.Printf("Group Signature verify err: %v\n", err)
	fmt.Printf("\n")
	groupPrivateKey, _ := share.RecoverSecret(suite.G2(), dkgShares, t, n)
	fmt.Printf("Group Private key: %v\n", groupPrivateKey)
	fmt.Printf("\n")
	_allSig, _ := bls.Sign(suite, groupPrivateKey, msg)
	fmt.Printf("Group Signature 2: %x\n", _allSig)
	fmt.Printf("\n")
}

func bls_test2() {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := kyber12381.NewSuite()
	e := geth12381.NewPairingEngine()
	gg1, gg2 := e.G1, e.G2
	private, public := bls.NewKeyPair(suite, random.New())
	sig, _ := bls.Sign(suite, private, msg)
	err := bls.Verify(suite, public, msg, sig)
	if err != nil {
		fmt.Printf("not verify: %v", err)
	} else {
		fmt.Printf("verified bls sig\n")
	}

	private1, public1 := bls.NewKeyPair(suite, random.New())
	private2, public2 := bls.NewKeyPair(suite, random.New())
	private3, public3 := bls.NewKeyPair(suite, random.New())
	sig1, err := bls.Sign(suite, private1, msg)
	sig2, err := bls.Sign(suite, private2, msg)
	sig3, err := bls.Sign(suite, private3, msg)
	aggregatedSig, err := bls.AggregateSignatures(suite, sig1, sig3, sig2)
	aggregatedKey := bls.AggregatePublicKeys(suite, public1, public2, public3)
	fmt.Printf("sig(%d): %x\n", len(aggregatedSig), aggregatedSig)
	_key, _ := aggregatedKey.MarshalBinary()
	fmt.Printf("pub key (%d): %x\n", len(_key), _key)
	fmt.Println()

	g1 := kilic12381.NewG1()
	recoveredSig, _ := g1.FromCompressed(aggregatedSig)
	fmt.Printf("recovered sig: %v\n", recoveredSig)
	s_sig := g1.ToUncompressed(recoveredSig)
	fmt.Printf("s_sig(%d): %x\n", len(s_sig), s_sig)
	b1 := make([]byte, 128)
	copy(b1[16:64], s_sig[:48])
	copy(b1[80:128], s_sig[48:96])
	fmt.Println()

	g2 := kilic12381.NewG2()
	recoveredPub, _ := g2.FromCompressed(_key)
	fmt.Printf("recovered pub: %v\n", recoveredPub)
	s_pub := g2.ToUncompressed(recoveredPub)
	fmt.Printf("s_pub(%d): %x\n", len(s_pub), s_pub)
	b2 := make([]byte, 256)
	copy(b2[16:64], s_pub[48:96])
	copy(b2[80:128], s_pub[:48])
	copy(b2[144:192], s_pub[144:192])
	copy(b2[208:256], s_pub[96:144])
	fmt.Println()

	g2Base := g2.One()
	fmt.Printf("g2(%d) base: %x\n", len(g2.ToUncompressed(g2Base)), g2.ToUncompressed(g2Base))
	g2s := make([]byte, 256)
	copy(g2s[16:64], g2.ToUncompressed(g2Base)[48:96])
	copy(g2s[80:128], g2.ToUncompressed(g2Base)[:48])
	copy(g2s[144:192], g2.ToUncompressed(g2Base)[144:192])
	copy(g2s[208:256], g2.ToUncompressed(g2Base)[96:144])
	g2base, err := gg2.DecodePoint(g2s)
	fmt.Printf("geth g2base: %v\n", g2base)
	fmt.Println()

	var Domain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	HM, _ := kilic12381.NewG1().HashToCurve(msg, Domain)
	fmt.Printf("HM(%d): %x\n", len(g1.ToUncompressed(HM)), g1.ToUncompressed(HM))
	hms := make([]byte, 128)
	copy(hms[16:], g1.ToUncompressed(HM)[:48])
	copy(hms[80:], g1.ToUncompressed(HM)[48:])
	hm, err := gg1.DecodePoint(hms)
	fmt.Printf("geth hm: %v\n", hm)
	fmt.Println()

	b3 := make([]byte, 384)
	copy(b3[:128], b1[:])
	copy(b3[128:], b2[:])
	fmt.Printf("b3(%d): %x\n", len(b3), b3)
	fmt.Println()

	pp2, err := gg2.FromBytes(s_pub)
	if err != nil {
		fmt.Printf("pp2 err %v, %v\n", pp2, err)
	} else {
		fmt.Printf("pp2 no err %v, %v\n", pp2, err)
	}
	fmt.Println()

	t0, t1, t2 := 0, 128, 384
	p1, err := gg1.DecodePoint(b3[t0:t1])
	fmt.Printf("err 1: %v, %x\n", err, b3[t0:t1])
	p2, err := gg2.DecodePoint(b3[t1:t2])
	fmt.Printf("err 2: %v, %x\n", err, b3[t1:t2])
	fmt.Println()

	p1neg := gg1.One()
	gg1.Neg(p1neg, p1)
	fmt.Printf("p1: %x\n", gg1.EncodePoint(p1))
	fmt.Printf("p1 neg: %x\n", gg1.EncodePoint(p1neg))
	fmt.Println()

	/*
		fmt.Printf("b2: %x\n", b2)
		fmt.Printf("s_pub: %x\n", s_pub)
		_, err_b2 := gg2.DecodePoint(b2)
		_, err_s_pub := gg2.FromBytes(s_pub)
		gg2.ToBytes(pp2)
		fmt.Printf("err b2: %v, err s pub: %v\n", err_b2, err_s_pub)
		fmt.Println()
	*/

	if !gg1.InCorrectSubgroup(p1) {
		fmt.Printf("error p1\n")
	}
	if !gg2.InCorrectSubgroup(pp2) {
		fmt.Printf("error p2\n")
	}

	//r1 := e.AddPair(hm, p2).Result()
	//r2 := e.AddPair(p1, g2base).Result()
	//fmt.Printf("r1: %v\n", r1)
	//fmt.Printf("r2: %v\n", r2)
	//fmt.Printf("r1 == r2: %t\n", r1.Equal(r2))
	e.AddPair(hm, p2)
	e.AddPairInv(p1, g2base)
	result := e.Check()
	fmt.Printf("e.check 1: %t\n", result)

	e.Reset()
	e.AddPair(hm, p2)
	e.AddPair(p1neg, g2base)
	result = e.Check()
	fmt.Printf("e.check neg: %t\n", result)
	fmt.Println()

	fmt.Println("---------BLS Verify Input-----------")
	fmt.Printf("g1(%d): %x\n", len(gg1.EncodePoint(hm)), gg1.EncodePoint(hm))
	fmt.Printf("g2(%d): %x\n", len(gg2.EncodePoint(p2)), gg2.EncodePoint(p2))
	fmt.Println("-------------------------")
	fmt.Printf("g1(%d): %x\n", len(gg1.EncodePoint(p1neg)), gg1.EncodePoint(p1neg))
	fmt.Printf("g2(%d): %x\n", len(gg2.EncodePoint(g2base)), gg2.EncodePoint(g2base))
	fmt.Println("-------------------------")
	all := make([]byte, 384*2)
	copy(all[:128], gg1.EncodePoint(hm)[:])
	copy(all[128:384], gg2.EncodePoint(p2)[:])
	copy(all[384:512], gg1.EncodePoint(p1neg)[:])
	copy(all[512:], gg2.EncodePoint(g2base)[:])
	fmt.Printf("all valid(%d): 0x%x\n", len(all), all)
	fmt.Println()

	all_invalid := make([]byte, 384*2)
	copy(all_invalid[:128], gg1.EncodePoint(hm)[:])
	copy(all_invalid[128:384], gg2.EncodePoint(p2)[:])
	copy(all_invalid[384:512], gg1.EncodePoint(hm)[:])
	copy(all_invalid[512:], gg2.EncodePoint(g2base)[:])
	fmt.Printf("all invalid(%d): 0x%x\n", len(all_invalid), all_invalid)
	fmt.Println()

	err = bls.Verify(suite, aggregatedKey, msg, aggregatedSig)
	if err != nil {
		fmt.Printf("aggregated not verify: %v", err)
	} else {
		fmt.Printf("aggregated verified bls sig\n")
	}

}

func main() {
	//bls_test1()
	bls_test2()
}
