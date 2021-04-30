package main

import (
	"bytes"
	"crypto/cipher"
	"fmt"

	kyber "go.dedis.ch/kyber"
	ecies "go.dedis.ch/kyber/encrypt/ecies"
	ed25519 "go.dedis.ch/kyber/group/edwards25519"
	"go.dedis.ch/kyber/pairing/bn256"
	share "go.dedis.ch/kyber/share"
	bls "go.dedis.ch/kyber/sign/bls"
	eddsa "go.dedis.ch/kyber/sign/eddsa"
	tbls "go.dedis.ch/kyber/sign/tbls"
	random "go.dedis.ch/kyber/util/random"
	//"reflect"
)

func bls_test1() {
	msg := []byte("Hello World")
	suite := bn256.NewSuite()
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
	/*
		// verify public key and private key matches
		for i := 0; i < n; i++ {
			fmt.Printf(
				"pubkey prikey %v\n%v\n\n",
				suite.G2().Point().Mul(dkgShares[i].V, nil),
				dkgPubShares[i].V,
			)
		}*/

	/*
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
		fmt.Printf("%v, %v\n", allSig, err)
		err = bls.Verify(suite, pubPolyAll.Commit(), msg, allSig)
		if err != nil {
			fmt.Printf("allsig verify failed, %v\n", err)
		} else {
			fmt.Printf("yeah!!!! %v\n", err)
		}

		// check if we can recover private ploy from t prishares
		for i := 0; i < n; i++ {
			priSharesSlice := priShares[i][:t]
			recoveredPriPoly, _ := share.RecoverPriPoly(suite.G2(), priSharesSlice, t, t)

			for j := 0; j < n; j++ {
				_s := recoveredPriPoly.Eval(priShares[i][j].I)
				if !reflect.DeepEqual(_s, priShares[i][j]) {
					fmt.Printf("not equal at t\n%v\n%v\n", _s, priShares[i][j])
				} else {
					fmt.Printf("equal\n")
				}
			}
		}

		fmt.Println("\n\n========================================================\n\n")

		for i := 0; i < 100; i++ {
			suite25519 := ed25519.NewBlakeSHA256Ed25519()
			private := suite25519.Scalar().Pick(random.New())
			public := suite25519.Point().Mul(private, nil)
			var buffer1 bytes.Buffer
			private.MarshalTo(&buffer1)
			privateBytes := buffer1.Bytes()
			var buffer2 bytes.Buffer
			public.MarshalTo(&buffer2)
			publicBytes := buffer2.Bytes()
			fmt.Printf("public[%d]: %v, %v, private[%d]: %v, %v\n", len(publicBytes), publicBytes, public, len(privateBytes), privateBytes, private)
		}
	*/
}

func bls_test2() {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
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

	err = bls.Verify(suite, aggregatedKey, msg, aggregatedSig)
	if err != nil {
		fmt.Printf("aggregated not verify: %v", err)
	} else {
		fmt.Printf("aggregated verified bls sig\n")
	}

}

type constantStream struct {
	seed []byte
}

func ConstantStream(buff []byte) cipher.Stream {
	return &constantStream{buff}
}

func (cs *constantStream) XORKeyStream(dst, src []byte) {
	copy(dst, cs.seed)
}

func ed25519_test1() {
	suite := ed25519.NewBlakeSHA256Ed25519()
	message := []byte("hello, world")

	// get a edDSA instance
	private := suite.Scalar().Pick(random.New())
	var buf bytes.Buffer
	private.MarshalTo(&buf)
	stream := ConstantStream(buf.Bytes())
	edDSA := eddsa.NewEdDSA(stream)

	if sig, err := edDSA.Sign(message); err != nil {
		fmt.Printf("err: %v", err)
	} else {
		if err := eddsa.Verify(edDSA.Public, message, sig); err != nil {
			fmt.Printf("err: %v", err)
		} else {
			fmt.Printf("Yes!\n")
		}
	}
}

func ed25519_test2() {
	suite := ed25519.NewBlakeSHA256Ed25519()
	message := []byte("hello, world")

	// get a edDSA instance
	private := suite.Scalar().Pick(random.New())
	var buf bytes.Buffer
	private.MarshalTo(&buf)
	stream := ConstantStream(buf.Bytes())
	edDSA := eddsa.NewEdDSA(stream)

	encrypted, _ := ecies.Encrypt(suite, edDSA.Public, message, suite.Hash)
	fmt.Printf("Encrypted: %x\n", encrypted)
	decrypted, _ := ecies.Decrypt(suite, edDSA.Secret, encrypted, suite.Hash)
	fmt.Printf("Original: %s\n", decrypted)
}

func shamir() {
	// use ecc curve edwards25519
	g := ed25519.NewBlakeSHA256Ed25519()

	// 5/5 (full) threshold
	n := 5
	t := n

	// poly is the polynomial we will generate locally
	poly := share.NewPriPoly(g, t, nil, g.RandomStream())
	fmt.Printf("Coefficient are:\n")
	coefficients := poly.Coefficients()
	for i, coeff := range coefficients {
		fmt.Printf("(%d/%d) %v", i, len(coefficients), coeff)
		if i == 0 {
			fmt.Printf(" (private key seed)\n")
		} else {
			fmt.Printf("\n")
		}
	}

	// get n points from the polynominal
	points := poly.Shares(n)
	fmt.Printf("\n")
	fmt.Printf("Points are:\n")
	for i, p := range points {
		fmt.Printf("(%d/%d) x=%d, y=%v\n", i, len(points), p.I+1, p.V)
	}

	// recovered private key seed
	recovered, _ := share.RecoverSecret(g, points, t, n)
	fmt.Printf("\n")
	fmt.Printf("The following two should be the same:\n")
	fmt.Printf("Recovered private key seed: %v\n", recovered)
	fmt.Printf("Private key from polynomial: %v\n", poly.Secret())
}

func main() {
	bls_test1()
	//bls_test2()
	//ed25519_test1()
	//ed25519_test2()
	//shamir()
}
