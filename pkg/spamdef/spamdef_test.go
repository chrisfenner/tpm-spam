package spamdef_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"
	_ "github.com/golang/protobuf/proto"

	"github.com/chrisfenner/tpm-spam/pkg/spamdef"
)

func TestSpamTemplate(t *testing.T) {
	policy, err := hex.DecodeString("3c326323670e28ad37bd57f63b4cc34d26ab205ef22f275c58d47fab2485466e")
	if err != nil {
		t.Fatalf("error decoding policy hex string: %v", err)
	}
	expected := tpm2.NVPublic{
		NVIndex:    tpmutil.Handle(0x017F0008),
		NameAlg:    tpm2.AlgSHA256,
		Attributes: 0x4A041008,
		AuthPolicy: tpmutil.U16Bytes(policy),
		DataSize:   64,
	}
	template, err := spamdef.Template(8)
	if err != nil {
		t.Fatalf("error calling SpamTemplate: %v", err)
	}
	if template.NVIndex != expected.NVIndex {
		t.Errorf("want NVIndex %v got %v", expected.NVIndex, template.NVIndex)
	}
	if template.NameAlg != expected.NameAlg {
		t.Errorf("want NameAlg %v got %v", expected.NameAlg, template.NameAlg)
	}
	if template.Attributes != expected.Attributes {
		t.Errorf("want Attributes %v got %v", expected.Attributes, template.Attributes)
	}
	if !bytes.Equal(template.AuthPolicy, expected.AuthPolicy) {
		t.Errorf("want AuthPolicy %v got %v", hex.EncodeToString(expected.AuthPolicy), hex.EncodeToString(template.AuthPolicy))
	}
	if template.DataSize != expected.DataSize {
		t.Errorf("want DataSize %v got %v", expected.DataSize, template.DataSize)
	}
}

func TestSpamPolicy(t *testing.T) {
	policy, err := spamdef.Policy(crypto.SHA256)
	if err != nil {
		t.Fatalf("error calling SpamPolicy: %v", err)
	}
	expectedHash, err := hex.DecodeString("3c326323670e28ad37bd57f63b4cc34d26ab205ef22f275c58d47fab2485466e")
	if err != nil {
		t.Fatalf("error decoding expected hex string: %v", err)
	}
	if !bytes.Equal(policy, expectedHash) {
		t.Errorf("want %v\ngot %v\n", expectedHash, policy)
	}
}

func TestSpamName(t *testing.T) {
	cases := []struct {
		index   uint16
		nameHex string
	}{
		{
			1,
			"000b256250663b977f359f82de770683b95e2e9323920fe69e28c95750852cf8bd74",
		},
		{
			3,
			"000b31a905aa2c259dcef4dd689fbb70dde96f90384fe3f9b7a6f6fb4f7cffc39d8e",
		},
	}
	for i, testCase := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			expectedName, err := hex.DecodeString(testCase.nameHex)
			if err != nil {
				t.Fatalf("error decoding expected hex string: %v", err)
			}
			name, err := spamdef.Name(testCase.index)
			if err != nil {
				t.Errorf("error from SpamName: %v", err)
			} else {
				if !bytes.Equal(name, expectedName) {
					t.Errorf("want\n%v\ngot\n%v\n",
						hex.EncodeToString(expectedName),
						hex.EncodeToString(name))
				}
			}
		})
	}
}
