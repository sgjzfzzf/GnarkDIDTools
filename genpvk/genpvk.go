package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/sgjzfzzf/GnarkDID"
)

type DefaultCircuit struct {
	data frontend.Variable
}

func (defaultCircuit *DefaultCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(defaultCircuit.data, 1)
	return nil
}

func main() {
	output := "key"
	input := ""
	for i, v := range os.Args {
		if v == "-o" || v == "--out" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				output = os.Args[i+1]
			}
		} else if v == "-i" || v == "--in" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				input = os.Args[i+1]
			}
		}
	}
	if input == "" {
		fmt.Fprintf(os.Stderr, "cannot find input r1cs\n")
		return
	} else {
		file, err := os.Open(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open r1cs\n")
			return
		}
		r1cs := groth16.NewCS(ecc.BN254)
		if err != nil {
			fmt.Fprintf(os.Stderr, "err: %s\n", err)
			return
		}
		_, err = r1cs.ReadFrom(file)
		file.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read from r1cs file\n")
			return
		}
		_, _, err = GnarkDID.GenerateSavePVKey(r1cs, output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot generate and save pk or vk\n")
			return
		}
	}
}
