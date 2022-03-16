package main

import (
	"GnarkDIDTools/dcircuit"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
)

func main() {
	output := "dcircuit"
	for i, v := range os.Args {
		if v == "-o" || v == "--out" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				output = os.Args[i+1]
			}
		}
	}
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &dcircuit.DCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot compile the r1cs, err: %s\n", err)
		return
	}
	file, err := os.Create(fmt.Sprintf("%s.r1cs", output))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create the file %s, err: %s\n", output, err)
		return
	}
	_, err = r1cs.WriteTo(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot write r1cs into file, error: %s\n", err)
		return
	}
	file.Close()
}
