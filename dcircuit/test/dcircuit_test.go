package dcircuit_test

import (
	"GnarkDIDTools/dcircuit"
	"os"
	"testing"
)

func TestInitializer(t *testing.T) {
	file, err := os.Open("./dircuit_obj.json")
	defer file.Close()
	if err != nil {
		t.FailNow()
	}
	rawInitializer, err := dcircuit.NewInitiallizer(file)
	if err != nil {
		t.FailNow()
	}
	initializer := dcircuit.Initializer{
		ID:               1,
		Name:             "Alice",
		BirthYear:        2000,
		Income:           10000,
		GraduationSchool: "Shanghai Jiao Tong University",
		Gender:           "Female",
		Property:         10000,
		Citizenship:      "China",
	}
	if rawInitializer != initializer {
		t.FailNow()
	}
}
