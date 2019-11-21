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
	"reflect"
)

func bls_test1() {
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

	for _, pubshares := range pubShares {
		for _, pubshare := range pubshares {
			b, _ := pubshare.V.MarshalBinary()
			//fmt.Printf("pubshare.V.MarshalBinary: %s, %s, %s, %s\n", hex.EncodeToString(b[:32]), hex.EncodeToString(b[32:64]), hex.EncodeToString(b[64:96]), hex.EncodeToString(b[96:]))
			V := suite.G2().Point()
			//fmt.Printf("%d, %d, %d, %d\n", V.ElementSize(), V.MarshalSize())
			V.UnmarshalBinary(b)
			//fmt.Printf("share.V & V: %t, %v, %v\n", pubshare.V.Equal(V), pubshare.V, V)
			pubshare.V = V
		}
	}

	for i, pubshares := range pubShares {
		pubpoly, _ := share.RecoverPubPoly(
			suite.G2(),
			pubshares,
			t,
			n,
		)
		v1, v2 := pubPolyList[i].Info()
		v3, v4 := pubpoly.Info()
		fmt.Printf("pubpoly before: %v\n%v\n", v1, v2)
		fmt.Printf("pubpoly rebuild: %v\n%v\n", v3, v4)
	}

	// this is the recovered private share for the combine private poly for each node
	dkgShares := make([]*share.PriShare, n)
	for i := 0; i < n; i++ {
		acc := suite.G2().Scalar().Zero()
		fmt.Printf("acc %d\n", acc)
		for j := 0; j < n; j++ { // assuming all participants are in the qualified set
			acc = suite.G2().Scalar().Add(acc, priShares[j][i].V)
			fmt.Printf("acc %d\n", acc)
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
		fmt.Printf("pubshare eval i=%d, v=%v\n", i, dkgPubShares[i].V)
	}

	// verify public key and private key matches
	for i := 0; i < n; i++ {
		fmt.Printf(
			"pubkey prikey %v\n%v\n\n",
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
	//bls_test1()
	//bls_test2()
	//ed25519_test1()
	//ed25519_test2()
	shamir()
}
