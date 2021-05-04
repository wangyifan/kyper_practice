package main

import (
	"fmt"

	ed25519 "go.dedis.ch/kyber/v3/group/edwards25519"
	share "go.dedis.ch/kyber/v3/share"
)

func shamir() {
	// use ecc curve edwards25519
	g := ed25519.NewBlakeSHA256Ed25519()

	// 5/5 (full) threshold
	n := 5
	t := n
	fmt.Printf("Degree of ploynomial = %d, number of coefficients = %d\n", n-1, n)

	// poly is the polynomial we will generate locally
	poly := share.NewPriPoly(g, t, nil, g.RandomStream())
	fmt.Printf("\n")
	fmt.Printf("Coefficients are:\n")
	coefficients := poly.Coefficients()
	for i, coeff := range coefficients {
		fmt.Printf("(%d/%d) %v", i+1, len(coefficients), coeff)
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
		fmt.Printf("(%d/%d) x=%d, y=%v\n", i+1, len(points), p.I+1, p.V)
	}

	// recovered private key seed
	recovered, _ := share.RecoverSecret(g, points, t, n)
	fmt.Printf("\n")
	fmt.Printf("The following two should be the same:\n")
	fmt.Printf("Recovered private key seed: %v\n", recovered)
	fmt.Printf("Private key from polynomial: %v\n", poly.Secret())
}

func main() {
	shamir()
}
