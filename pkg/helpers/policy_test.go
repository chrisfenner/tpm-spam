package helpers_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"github.com/chrisfenner/tpm-spam/pkg/helpers"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/protobuf/encoding/prototext"
	"testing"
)

func policyFromTextpb(textpb string) *policypb.Policy {
	var policy policypb.Policy
	if err := prototext.Unmarshal([]byte(textpb), &policy); err != nil {
		panic(err)
	}
	return &policy
}

func ruleFromTextpb(textpb string) *policypb.Rule {
	var rule policypb.Rule
	if err := prototext.Unmarshal([]byte(textpb), &rule); err != nil {
		panic(err)
	}
	return &rule
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		name   string
		policy *policypb.Policy
		normal [][]*policypb.Rule
	}{
		{
			"and of two ors",
			policyFromTextpb(`
and {
  policy { or {
    policy { rule {
      spam { index: 1 offset: 32 comparison: EQ operand: "foo" }
    } }
    policy { rule {
      spam { index: 1 offset: 32 comparison: EQ operand: "bar" }
    } }
  } }
  policy { or {
    policy { rule {
      spam { index: 1 offset: 36 comparison: EQ operand: "baz" }
    } }
    policy { rule {
      spam { index: 1 offset: 36 comparison: EQ operand: "qux" }
    } }
  } }
}
			`),
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 32 comparison: EQ operand: "foo" }
					`),
					ruleFromTextpb(`
spam { index: 1 offset: 36 comparison: EQ operand: "baz" }
					`),
				},
				{
					ruleFromTextpb(`
spam { index: 1 offset: 32 comparison: EQ operand: "foo" }
					`),
					ruleFromTextpb(`
spam { index: 1 offset: 36 comparison: EQ operand: "qux" }
					`),
				},
				{
					ruleFromTextpb(`
spam { index: 1 offset: 32 comparison: EQ operand: "bar" }
					`),
					ruleFromTextpb(`
spam { index: 1 offset: 36 comparison: EQ operand: "baz" }
					`),
				},
				{
					ruleFromTextpb(`
spam { index: 1 offset: 32 comparison: EQ operand: "bar" }
					`),
					ruleFromTextpb(`
spam { index: 1 offset: 36 comparison: EQ operand: "qux" }
					`),
				},
			},
		},
		{
			"or of two ands",
			policyFromTextpb(`
or {
  policy { and {
    policy { rule {
      spam { index: 1 offset: 32 comparison: EQ operand: "foo" }
    } }
    policy { rule {
      spam { index: 1 offset: 36 comparison: EQ operand: "baz" }
    } }
  } }
  policy { and {
    policy { rule {
      spam { index: 1 offset: 32 comparison: EQ operand: "bar" }
    } }
    policy { rule {
      spam { index: 1 offset: 36 comparison: EQ operand: "qux" }
    } }
  } }
}
			`),
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 32 comparison: EQ operand: "foo" }
					`),
					ruleFromTextpb(`
spam { index: 1 offset: 36 comparison: EQ operand: "baz" }
					`),
				},
				{
					ruleFromTextpb(`
spam { index: 1 offset: 32 comparison: EQ operand: "bar" }
					`),
					ruleFromTextpb(`
spam { index: 1 offset: 36 comparison: EQ operand: "qux" }
					`),
				},
			},
		},
		{
			"and/or/and",
			policyFromTextpb(`
and {
  policy { or {
    policy { and {
      policy { rule {
        spam { operand: "a" }
      } }
      policy { rule {
        spam { operand: "b" }
      } }
    } }
    policy { and {
      policy { rule {
        spam { operand: "c" }
      } }
      policy { rule {
        spam { operand: "d" }
      } }
    } }
  } }
  policy { or {
    policy { and {
      policy { rule {
        spam { operand: "e" }
      } }
      policy { rule {
        spam { operand: "f" }
      } }
    } }
    policy { and {
      policy { rule {
        spam { operand: "g" }
      } }
      policy { rule {
        spam { operand: "h" }
      } }
    } }
  } }
}
			`),
			[][]*policypb.Rule{
				{
					ruleFromTextpb(` spam { operand: "a" } `),
					ruleFromTextpb(` spam { operand: "b" } `),
					ruleFromTextpb(` spam { operand: "e" } `),
					ruleFromTextpb(` spam { operand: "f" } `),
				},
				{
					ruleFromTextpb(` spam { operand: "a" } `),
					ruleFromTextpb(` spam { operand: "b" } `),
					ruleFromTextpb(` spam { operand: "g" } `),
					ruleFromTextpb(` spam { operand: "h" } `),
				},
				{
					ruleFromTextpb(` spam { operand: "c" } `),
					ruleFromTextpb(` spam { operand: "d" } `),
					ruleFromTextpb(` spam { operand: "e" } `),
					ruleFromTextpb(` spam { operand: "f" } `),
				},
				{
					ruleFromTextpb(` spam { operand: "c" } `),
					ruleFromTextpb(` spam { operand: "d" } `),
					ruleFromTextpb(` spam { operand: "g" } `),
					ruleFromTextpb(` spam { operand: "h" } `),
				},
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			normalized, err := helpers.Normalize(testCase.policy)
			if err != nil {
				t.Errorf("error from Normalize: %v", err)
				return
			}
			if len(normalized) != len(testCase.normal) {
				t.Errorf("want %d ORs, got %d", len(testCase.normal), len(normalized))
				t.Logf("want:\n%+v\ngot:\n%+v\n", testCase.normal, normalized)
				return
			}
			for i := 0; i < len(normalized); i++ {
				if len(normalized[i]) != len(testCase.normal[i]) {
					t.Errorf("at index %d: want %d rules, got %d",
						i, len(testCase.normal[i]), len(normalized[i]))
					continue
				}
				for j := 0; j < len(normalized[i]); j++ {
					if !proto.Equal(normalized[i][j], testCase.normal[i][j]) {
						t.Errorf("at policy %d rule %d: want %v got %v",
							i, j, testCase.normal[i][j], normalized[i][j])
					}
				}
			}
		})
	}
}

func TestSpamPolicy(t *testing.T) {
	policy, err := helpers.SpamPolicy(crypto.SHA256)
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

func TestSpamTemplate(t *testing.T) {
	policy, err := hex.DecodeString("3c326323670e28ad37bd57f63b4cc34d26ab205ef22f275c58d47fab2485466e")
	if err != nil {
		t.Fatalf("error decoding policy hex string: %v", err)
	}
	expected := tpm2.NVPublic{
		NVIndex:    tpmutil.Handle(0x017F0008),
		NameAlg:    tpm2.AlgSHA256,
		Attributes: 0x4E041008,
		AuthPolicy: tpmutil.U16Bytes(policy),
		DataSize:   64,
	}
	template, err := helpers.SpamTemplate(8)
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

func TestExtendPolicy(t *testing.T) {
	// TODO
}

func TestCalculatePolicy(t *testing.T) {
	// TODO
}
