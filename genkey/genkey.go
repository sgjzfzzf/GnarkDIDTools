package main

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/sgjzfzzf/GnarkDID"
)

func randString(len int) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		b := r.Intn(26) + 65
		bytes[i] = byte(b)
	}
	return string(bytes)
}

func main() {
	output := "privatekey"
	seed := randString(256)
	for i, v := range os.Args {
		if v == "-o" || v == "--out" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				output = os.Args[i+1]
			}
		} else if v == "-s" || v == "--seed" {
			if i+1 >= len(os.Args) || os.Args[i+1][0] == '-' {
				fmt.Fprintf(os.Stderr, "cannot parse the command\n")
				return
			} else {
				seed = os.Args[i+1]
			}
		}
	}
	seedReader := strings.NewReader(seed)
	err := GnarkDID.GenerateSaveKey(seedReader, output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "errors happened during generation")
	}
}
