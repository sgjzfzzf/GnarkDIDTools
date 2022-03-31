package dcircuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type DCircuit struct {
	ID               frontend.Variable `gnark:"ID,public"` //uint64
	Name             frontend.Variable //string
	BirthYear        frontend.Variable //uint64
	Income           frontend.Variable //uint64
	GraduationSchool frontend.Variable //string
	GPA              frontend.Variable //uint64
	Gender           frontend.Variable //string
	Property         frontend.Variable //uint64
	Citizenship      frontend.Variable //string
	PublishYear      frontend.Variable //uint64
	PublishMonth     frontend.Variable //uint64
	Signature        eddsa.Signature
	Publickey        eddsa.PublicKey `gnark:"publickey,public"`
}

func (dcircuit *DCircuit) Define(api frontend.API) error {

	params, err := twistededwards.NewEdCurve(api.Curve())
	if err != nil {
		return err
	}
	dcircuit.Publickey.Curve = params
	hFunc, err := mimc.NewMiMC(api)
	hFunc.Reset()
	if err != nil {
		return err
	}
	hFunc.Write(
		dcircuit.ID,
		dcircuit.Name,
		dcircuit.BirthYear,
		dcircuit.Income,
		dcircuit.GraduationSchool,
		dcircuit.GPA,
		dcircuit.Gender,
		dcircuit.Property,
		dcircuit.Citizenship,
		dcircuit.PublishYear,
		dcircuit.PublishMonth,
	)
	hSum := hFunc.Sum()
	hFunc.Reset()
	err = eddsa.Verify(api, dcircuit.Signature, hSum, dcircuit.Publickey)
	if err != nil {
		return err
	}

	// TODO
	/*
		Define your own constraints there in the form of gnark.
	*/

	// Example 1:
	// maxGPA := api.ConstantValue(430)
	// api.AssertIsLessOrEqual(api.Sub(maxGPA, dcircuit.GPA), api.Sub(maxGPA, api.ConstantValue(370)))
	// unis := []string{"Shanghai Jiao Tong University", "Fudan University", "Tongji University", "East China Normal University"}
	// isTrue := api.FromBinary(1)
	// for _, uni := range unis {
	// 	res := api.Cmp(dcircuit.GraduationSchool, GnarkDID.TransferStringHashToElement(uni))
	// 	isTrue = api.Mul(res, isTrue)
	// }
	// api.AssertIsEqual(isTrue, api.ConstantValue(0))

	// Example 2:
	// maxIncome := api.ConstantValue(0x7fffffff)
	// api.AssertIsLessOrEqual(dcircuit.BirthYear, api.ConstantValue(time.Now().Year()-18))
	// api.AssertIsLessOrEqual(api.Sub(maxIncome, dcircuit.Income), api.Sub(maxIncome, api.ConstantValue(5000)))
	// nowTime := api.ConstantValue(time.Now().Year()*12 + int(time.Now().Month()))
	// pubTime := api.Add(api.Mul(dcircuit.PublishYear, 12), dcircuit.PublishMonth)
	// api.AssertIsLessOrEqual(api.Sub(nowTime, pubTime), api.ConstantValue(3))

	// Example 3:
	// api.AssertIsLessOrEqual(dcircuit.Property, api.ConstantValue(5000))
	// nowTime := api.ConstantValue(time.Now().Year()*12 + int(time.Now().Month()))
	// pubTime := api.Add(api.Mul(dcircuit.PublishYear, 12), dcircuit.PublishMonth)
	// api.AssertIsLessOrEqual(api.Sub(nowTime, pubTime), api.ConstantValue(3))

	// Example 4:
	// api.AssertIsLessOrEqual(dcircuit.BirthYear, api.ConstantValue(time.Now().Year()-60))
	// nowTime := api.ConstantValue(time.Now().Year()*12 + int(time.Now().Month()))
	// pubTime := api.Add(api.Mul(dcircuit.PublishYear, 12), dcircuit.PublishMonth)
	// api.AssertIsLessOrEqual(api.Sub(nowTime, pubTime), api.ConstantValue(3))

	return nil
}
