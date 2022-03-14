package dcircuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/sgjzfzzf/GnarkDID"
)

type Initializer struct {
	ID               uint64
	Name             string
	BirthYear        uint64
	Income           uint64
	GraduationSchool string
	Gender           rune
	Property         uint64
	Citizenship      string
}

func (initializer *Initializer) GenerateCircuit(sk eddsa.PrivateKey) (DCircuit, error) {
	dcircuit := DCircuit{}
	dcircuit.ID = initializer.ID
	dcircuit.Name = GnarkDID.TransferStringHashToElement(initializer.Name)
	dcircuit.BirthYear = initializer.BirthYear
	dcircuit.Income = initializer.Income
	dcircuit.GraduationSchool = GnarkDID.TransferStringHashToElement(initializer.GraduationSchool)
	dcircuit.Gender = uint64(initializer.Gender)
	dcircuit.Property = initializer.Property
	dcircuit.Citizenship = GnarkDID.TransferStringHashToElement(initializer.Citizenship)
	signature, err := initializer.GenerateSignature(sk)
	if err != nil {
		return dcircuit, err
	}
	dcircuit.Signature.S = signature.S
	dcircuit.Signature.R.X = signature.R.X
	dcircuit.Signature.R.Y = signature.R.Y
	dcircuit.Publickey.A.X = sk.PublicKey.A.X
	dcircuit.Publickey.A.Y = sk.PublicKey.A.Y
	return dcircuit, nil
}

func (initializer *Initializer) GenerateSignature(sk eddsa.PrivateKey) (eddsa.Signature, error) {
	hFunc := mimc.NewMiMC()
	element := fr.NewElement(initializer.ID)
	bytes := element.Bytes()
	_, err := hFunc.Write(bytes[:])
	if err != nil {
		return eddsa.Signature{}, err
	}

	element = GnarkDID.TransferStringHashToElement(initializer.Name)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return eddsa.Signature{}, err
	}

	element = fr.NewElement(initializer.BirthYear)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return eddsa.Signature{}, err
	}

	element = fr.NewElement(initializer.Income)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return eddsa.Signature{}, err
	}

	element = GnarkDID.TransferStringHashToElement(initializer.GraduationSchool)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return eddsa.Signature{}, err
	}

	element = fr.NewElement(uint64(initializer.Gender))
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return eddsa.Signature{}, err
	}

	element = fr.NewElement(initializer.Property)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return eddsa.Signature{}, err
	}
	element = GnarkDID.TransferStringHashToElement(initializer.Citizenship)
	bytes = element.Bytes()
	_, err = hFunc.Write(bytes[:])
	if err != nil {
		return eddsa.Signature{}, err
	}

	hSum := hFunc.Sum([]byte{})
	hFunc.Reset()
	rawSign, err := sk.Sign(hSum, hFunc)
	if err != nil {
		return eddsa.Signature{}, err
	}
	signature := eddsa.Signature{}
	signature.SetBytes(rawSign)
	return signature, nil
}
