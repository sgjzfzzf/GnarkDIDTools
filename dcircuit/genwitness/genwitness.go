package main

import (
	"GnarkDIDTools/dcircuit"
	"fmt"
	"os"

	"github.com/sgjzfzzf/GnarkDID"
)

func main() {
	output := "witness"
	input := ""
	key := ""
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
		} else if v == "-k" || v == "--key" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				key = os.Args[i+1]
			}
		}
	}

	if input != "" && key != "" {
		file, err := os.Open(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot find input file\n")
			return
		}
		initializer, err := dcircuit.NewInitiallizer(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open input file\n")
		}
		file.Close()
		file, err = os.Open(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot find private key file\n")
			return
		}
		sk, err := GnarkDID.ReadSavedPrivateKey(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read private key file\n")
			return
		}
		file.Close()
		file, err = os.Create(fmt.Sprintf("%s.wit", output))
		_, err = initializer.GenerateSaveWitness(sk, file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot save witness file\n")
			return
		}
		file.Close()
	} else {
		fmt.Fprintf(os.Stderr, "cannot find the input parameter\n")
	}

}
