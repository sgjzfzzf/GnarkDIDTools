package main

import (
	"GnarkDIDTools/dcircuit"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/sgjzfzzf/GnarkDID"
)

func main() {
	input := ""
	pkey := ""
	output := "proof"
	r1csf := ""
	for i, v := range os.Args {
		if v == "-i" || v == "--in" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				input = os.Args[i+1]
			}
		} else if v == "-p" || v == "--pkey" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				pkey = os.Args[i+1]
			}
		} else if v == "-o" || v == "--out" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				output = os.Args[i+1]
			}
		} else if v == "-r" || v == "--r1cs" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				r1csf = os.Args[i+1]
			}
		}
	}

	if pkey != "" && r1csf != "" && input != "" {

		file, err := os.Open(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open the witness file, err: %s", err)
			return
		}
		witness, err := dcircuit.ReadWitness(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read the witness file, err: %s", err)
			return
		}
		file.Close()

		file, err = os.Open(pkey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open the proving key file, err: %s", err)
			return
		}
		pk, err := GnarkDID.ReadSavedPKey(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read the saved proving key file, err: %s", err)
			return
		}
		file.Close()

		r1cs := groth16.NewCS(ecc.BN254)
		file, err = os.Open(r1csf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open the r1cs file, err: %s", err)
			return
		}
		_, err = r1cs.ReadFrom(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read the saved r1cs file, err: %s", err)
			return
		}
		file.Close()

		proof, err := groth16.Prove(r1cs, pk, witness)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot generate proof, err: %s\n", err)
			return
		}
		_, err = GnarkDID.SaveProof(proof, output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot save the proof, err: %s\n", err)
			return
		}
	} else {
		fmt.Fprintf(os.Stderr, "cannot find the input parameter\n")
	}

}
