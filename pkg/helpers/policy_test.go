package helpers_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"github.com/chrisfenner/tpm-spam/pkg/helpers"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/golang/protobuf/proto"
	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"
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

func TestSpamName(t *testing.T) {
	cases := []struct {
		index   uint32
		nameHex string
	}{
		{
			1,
			"0022000bfe198d7f6f167df8c554d5c075715fa56dcf39c29e9acad2f7bdaf36dbecbb59",
		},
		{
			3,
			"0022000b8c1f794ff7510373a142b6b7bdcfc120541aab0486941b31c90f0f8109ff4626",
		},
	}
	for i, testCase := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			expectedName, err := hex.DecodeString(testCase.nameHex)
			if err != nil {
				t.Fatalf("error decoding expected hex string: %v", err)
			}
			name, err := helpers.SpamName(testCase.index)
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

func TestExtendPolicy(t *testing.T) {
	cases := []struct {
		name    string
		hashHex string
		rule    *policypb.Rule
	}{
		{
			"eq",
			"00c5763e28c8a900f345a3901f4bdccd07a992e62b2ac3203b8e1f9a15c01d5a",
			ruleFromTextpb(`
spam { index: 1 offset: 32 comparison: EQ operand: "foo" }
			`),
		},
		{
			"neq",
			"f72f77ca6133727d1e6e763a264ef4c8d4b3adfc3f46500d437e5e5930609793",
			ruleFromTextpb(`
spam { index: 2 offset: 4 comparison: NEQ operand: "bar" }
			`),
		},
		{
			"gt",
			"3adeeaf7e0c74b2cafd1d8f19c1f1a0b2b0aadb551f1c4de65d9b3bcae36e1ff",
			ruleFromTextpb(`
spam { index: 3 offset: 0 comparison: GT operand: "\000\000\000\004" }
			`),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			expectedPolicy, err := hex.DecodeString(testCase.hashHex)
			if err != nil {
				t.Fatalf("error decoding expected hex string: %v", err)
			}
			currentPolicy := make([]byte, 32)
			policy, err := helpers.ExtendPolicy(crypto.SHA256, currentPolicy, testCase.rule)
			if err != nil {
				t.Errorf("error from ExtendPolicy: %v", err)
			} else {
				if !bytes.Equal(policy, expectedPolicy) {
					t.Errorf("want\n%v\ngot\n%v\n",
						hex.EncodeToString(expectedPolicy),
						hex.EncodeToString(policy))
				}
			}
		})
	}
}

func TestCalculatePolicy(t *testing.T) {
	cases := []struct {
		name    string
		hashHex string
		policy  *policypb.Policy
	}{
		{
			"single spam",
			"00c5763e28c8a900f345a3901f4bdccd07a992e62b2ac3203b8e1f9a15c01d5a",
			policyFromTextpb(`
rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } }
			`),
		},
		{
			"OR of 2 spams",
			"8c16ab4649cd3e357080cb9f398d8a6b2bab30c586df997ef8e94c5ef65983d4",
			policyFromTextpb(`
or {
	policy { rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } } }
	policy { rule { spam { index: 2 offset: 4 comparison: NEQ operand: "bar" } } }
}
			`),
		},
		{
			"unnecessary AND",
			"00c5763e28c8a900f345a3901f4bdccd07a992e62b2ac3203b8e1f9a15c01d5a",
			policyFromTextpb(`
and { policy { rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } } } }
			`),
		},
		{
			"two unnecessary ANDs",
			"00c5763e28c8a900f345a3901f4bdccd07a992e62b2ac3203b8e1f9a15c01d5a",
			policyFromTextpb(`
and { policy { and { policy { rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } } } } } }
			`),
		},
		{
			"unnecessary OR",
			"00c5763e28c8a900f345a3901f4bdccd07a992e62b2ac3203b8e1f9a15c01d5a",
			policyFromTextpb(`
or { policy { rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } } } }
			`),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			expectedPolicy, err := hex.DecodeString(testCase.hashHex)
			if err != nil {
				t.Fatalf("error decoding expected hex string: %v", err)
			}
			policy, err := helpers.CalculatePolicy(testCase.policy, crypto.SHA256)
			if err != nil {
				t.Errorf("error from CalculatePolicy: %v", err)
			} else {
				if !bytes.Equal(policy, expectedPolicy) {
					t.Errorf("want\n%v\ngot\n%v\n",
						hex.EncodeToString(expectedPolicy),
						hex.EncodeToString(policy))
				}
			}
		})
	}
}

// Test a bunch of policies that should all be satisfied with the same simple state.
func TestSatisfiablePolicies(t *testing.T) {
	tpmState := helpers.TpmState{
		Spams: map[uint32]helpers.SpamContents{
			1: [64]byte{
				0, 1, 2, 3, 4, 5, 6, 7,
				8, 9, 10, 11, 12, 13, 14, 15,
				16, 17, 18, 19, 20, 21, 22, 23,
				24, 25, 26, 27, 28, 29, 30, 31,
				32, 33, 34, 35, 36, 37, 38, 39,
				40, 41, 42, 43, 44, 45, 46, 47,
				48, 49, 50, 51, 52, 53, 54, 55,
				56, 57, 58, 59, 60, 61, 62, 63,
			},
		},
	}
	cases := []struct {
		name  string
		index int
		rules helpers.NormalizedPolicy
	}{
		{
			"simple EQ",
			0,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: EQ operand: "\x00\x01\x02\x03" }
					`),
				},
			},
		},
		{
			"simple NEQ",
			0,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: NEQ operand: "\x00\x01\x02\x04" }
					`),
				},
			},
		},
		{
			"simple GT",
			0,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: GT operand: "\x00\x01\x02\x02" }
					`),
				},
			},
		},
		{
			"simple LT",
			0,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: LT operand: "\x00\x01\x02\x04" }
					`),
				},
			},
		},
		{
			"simple GTE",
			0,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: GTE operand: "\x00\x01\x02\x03" }
					`),
				},
			},
		},
		{
			"simple LTE",
			0,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: LTE operand: "\x00\x01\x02\x03" }
					`),
				},
			},
		},
		{
			"simple BITSET",
			0,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: BITSET operand: "\x00\x00\x02\x00" }
					`),
				},
			},
		},
		{
			"simple BITCLEAR",
			0,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: BITCLEAR operand: "\xFF\x00\x01\x00" }
					`),
				},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			idx, err := helpers.FirstSatisfiable(testCase.rules, &tpmState)
			if err != nil {
				t.Errorf("got error from FirstSatisfiable: %v", err)
			} else {
				if *idx != testCase.index {
					t.Errorf("want %v got %v", testCase.index, *idx)
				}
			}
		})
	}
}
