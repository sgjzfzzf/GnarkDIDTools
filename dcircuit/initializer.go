package dcircuit

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/sgjzfzzf/GnarkDID"
)

type Initializer struct {
	ID               uint64
	Name             string
	BirthYear        uint64
	Income           uint64
	GraduationSchool string
	Gender           string
	Property         uint64
	Citizenship      string
}

func (initializer *Initializer) GenerateWitness(sk eddsa.PrivateKey) (*witness.Witness, error) {
	dcircuit := DCircuit{}
	dcircuit.ID = initializer.ID
	dcircuit.Name = GnarkDID.TransferStringHashToElement(initializer.Name)
	dcircuit.BirthYear = initializer.BirthYear
	dcircuit.Income = initializer.Income
	dcircuit.GraduationSchool = GnarkDID.TransferStringHashToElement(initializer.GraduationSchool)
	dcircuit.Gender = GnarkDID.TransferStringHashToElement(initializer.Gender)
	dcircuit.Property = initializer.Property
	dcircuit.Citizenship = GnarkDID.TransferStringHashToElement(initializer.Citizenship)
	signature, err := initializer.GenerateSignature(sk)
	if err != nil {
		return nil, err
	}
	dcircuit.Signature.S = signature.S[:]
	dcircuit.Signature.R.X = signature.R.X
	dcircuit.Signature.R.Y = signature.R.Y
	dcircuit.Publickey.A.X = sk.PublicKey.A.X
	dcircuit.Publickey.A.Y = sk.PublicKey.A.Y
	return frontend.NewWitness(&dcircuit, ecc.BN254)
}

func GeneratePublicWitness(pk eddsa.PublicKey) (*witness.Witness, error) {
	dcircuit := DCircuit{}
	dcircuit.ID = 0
	dcircuit.Name = 0
	dcircuit.BirthYear = 0
	dcircuit.Income = 0
	dcircuit.GraduationSchool = 0
	dcircuit.Gender = 0
	dcircuit.Property = 0
	dcircuit.Citizenship = 0
	dcircuit.Signature.S = 0
	dcircuit.Signature.R.X = 0
	dcircuit.Signature.R.Y = 0
	dcircuit.Publickey.A.X = pk.A.X
	dcircuit.Publickey.A.Y = pk.A.Y
	witness, err := frontend.NewWitness(&dcircuit, ecc.BN254)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot generate witness\n")
		return witness, err
	}
	return witness.Public()
}

func (initializer *Initializer) GenerateSignature(sk eddsa.PrivateKey) (eddsa.Signature, error) {
	hFunc := mimc.NewMiMC()
	hFunc.Reset()
	signature := eddsa.Signature{}
	element := fr.NewElement(initializer.ID)
	bytes := element.Bytes()
	_, err := hFunc.Write(bytes[:])
	if err != nil {
		return signature, err
	}

	element = GnarkDID.TransferStringHashToElement(initializer.Name)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return signature, err
	}

	element.SetUint64(initializer.BirthYear)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return signature, err
	}

	element.SetUint64(initializer.Income)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return signature, err
	}

	element = GnarkDID.TransferStringHashToElement(initializer.GraduationSchool)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return signature, err
	}

	element = GnarkDID.TransferStringHashToElement(initializer.Gender)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return signature, err
	}

	element.SetUint64(initializer.Property)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return signature, err
	}

	element = GnarkDID.TransferStringHashToElement(initializer.Citizenship)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return signature, err
	}

	hSum := hFunc.Sum([]byte{})
	hFunc.Reset()
	rawSign, err := sk.Sign(hSum, hFunc)
	if err != nil {
		return signature, err
	}
	signature.SetBytes(rawSign)
	return signature, nil
}

func NewInitiallizer(file *os.File) (Initializer, error) {
	initializer := Initializer{}
	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return initializer, err
	}
	err = json.Unmarshal(bytes, &initializer)
	return initializer, err
}
