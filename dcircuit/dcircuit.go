package dcircuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type DCircuit struct {
	ID               frontend.Variable //uint64
	Name             frontend.Variable //string
	BirthYear        frontend.Variable //uint64
	Income           frontend.Variable //uint64
	GraduationSchool frontend.Variable //string
	Gender           frontend.Variable //string
	Property         frontend.Variable //uint64
	Citizenship      frontend.Variable //string
	Signature        eddsa.Signature   `gnark:"signature,public"`
	Publickey        eddsa.PublicKey   `gnark:"publickey,public"`
}

func (dcircuit *DCircuit) Define(api frontend.API) error {

	params, err := twistededwards.NewEdCurve(api.Curve())
	if err != nil {
		return err
	}
	dcircuit.Publickey.Curve = params
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hFunc.Write(dcircuit.ID,
		dcircuit.Name,
		dcircuit.BirthYear,
		dcircuit.Income,
		dcircuit.GraduationSchool,
		dcircuit.Gender,
		dcircuit.Property,
		dcircuit.Property,
		dcircuit.Citizenship,
		dcircuit.Publickey.A.X,
		dcircuit.Publickey.A.Y)
	hSum := hFunc.Sum()
	err = eddsa.Verify(api, dcircuit.Signature, hSum, dcircuit.Publickey)
	if err != nil {
		return err
	}

	// TODO
	/*
		Define your own constraints there in the form of gnark.
	*/

	return nil
}
