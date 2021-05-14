package tpmstate_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/chrisfenner/tpm-spam/pkg/spam"
	"github.com/chrisfenner/tpm-spam/pkg/tpmstate"
	"github.com/google/go-tpm-tools/simulator"
)

func TestCurrentTpmState(t *testing.T) {
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator")
	}
	defer tpm.Close()

	for i := uint16(1); i <= 6; i++ {
		if err := spam.Define(tpm, i, ""); err != nil {
			t.Fatalf("could not define test spams: %v", err)
		}
		defer spam.Undefine(tpm, i, "")
		data := [64]byte{}
		copy(data[:], fmt.Sprintf("%d cans of spam on the wall", i))
		if err := spam.Write(tpm, i, data); err != nil {
			t.Fatalf("could not write test spam: %v", err)
		}
	}

	state, err := tpmstate.CurrentTpmState(tpm)
	if err != nil {
		t.Fatalf("from CurrentTpmState: %v", err)
	}

	for i := uint16(1); i <= 6; i++ {
		got, ok := state.Spams[i]
		if !ok {
			t.Errorf("wanted to find spam %d", i)
		} else if want := fmt.Sprintf("%d cans of spam on the wall", i); !strings.HasPrefix(string(got[:]), want) {
			t.Errorf("want '%s' got '%s'", want, string(got[:]))
		}
	}
}
