package main

import (
	"GnarkDIDTools/dcircuit"
	"fmt"
	"os"
	"strconv"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/sgjzfzzf/GnarkDID"
)

func main() {
	prooff := ""
	vkf := ""
	pkf := ""
	ID := ""
	for i, v := range os.Args {
		if v == "-p" || v == "--proof" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				prooff = os.Args[i+1]
			}
		} else if v == "-v" || v == "--vkey" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				vkf = os.Args[i+1]
			}
		} else if v == "-k" || v == "--pubkey" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				pkf = os.Args[i+1]
			}
		} else if v == "-i" || v == "--id" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				ID = os.Args[i+1]
			}
		}
	}
	if prooff != "" && vkf != "" && pkf != "" {
		file, err := os.Open(prooff)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open proof file, err: %s\n", err)
			return
		}
		proof, err := GnarkDID.ReadSavedProof(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read saved proof, err: %s\n", err)
			return
		}
		file.Close()

		file, err = os.Open(vkf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open verifying key file, err: %s\n", err)
			return
		}
		vk, err := GnarkDID.ReadSavedVKey(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read saved verifying key file, err: %s\n", err)
			return
		}
		file.Close()

		file, err = os.Open(pkf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open saved public key file, err: %s\n", err)
			return
		}
		pk, err := GnarkDID.ReadSavedPublicKey(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read saved public key file, err: %s\n", err)
			return
		}
		file.Close()

		id, err := strconv.ParseUint(ID, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot parse the id, err: %s\n", err)
			return
		}
		publicWitness, err := dcircuit.GeneratePublicWitness(id, pk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot generate public witness, err: %s\n", err)
			return
		}

		err = groth16.Verify(proof, vk, publicWitness)
		if err == nil {
			fmt.Println("Right.")
		} else {
			fmt.Printf("Wrong.\n%s\n", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "cannot find input file")
	}
}
