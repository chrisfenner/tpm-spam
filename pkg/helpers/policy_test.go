package helpers_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"
	"github.com/chrisfenner/tpm-spam/pkg/eighttree"
	"github.com/chrisfenner/tpm-spam/pkg/helpers"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/chrisfenner/tpm-spam/pkg/spam"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm-tools/simulator"
	"google.golang.org/protobuf/encoding/prototext"
	"io"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

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
		index   uint16
		nameHex string
	}{
		{
			1,
			"000bf1f81900d5cc426fdf139d1cbf3e3c3edb67b26740e8a0313b1e4cfec503016e",
		},
		{
			3,
			"000b21a0b88cb141a41bf1fe66e6daf41e85e476c180dbceaeb4085b5e8e613b7db0",
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
			"e0897fdc351b072a0abefd9aff51d75634755ee6edb60807a3625667819b6d7a",
			ruleFromTextpb(`
spam { index: 1 offset: 32 comparison: EQ operand: "foo" }
			`),
		},
		{
			"neq",
			"18d46f2acbf4519f6f0efb1ac6f58967a565d4c6fa53516e7597066fe2f0716a",
			ruleFromTextpb(`
spam { index: 2 offset: 4 comparison: NEQ operand: "bar" }
			`),
		},
		{
			"gt",
			"d1c47217845f7e69fc9edf2fa3b6a91cc78c3df98b40eb9bd37f742ecea53d8d",
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
			"e0897fdc351b072a0abefd9aff51d75634755ee6edb60807a3625667819b6d7a",
			policyFromTextpb(`
rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } }
			`),
		},
		{
			"OR of 2 spams",
			"82f97b5a589664eef101b9e6fcb69bca388bb71299494202154d0eb206f190ed",
			policyFromTextpb(`
or {
	policy { rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } } }
	policy { rule { spam { index: 2 offset: 4 comparison: NEQ operand: "bar" } } }
}
			`),
		},
		{
			"unnecessary AND",
			"e0897fdc351b072a0abefd9aff51d75634755ee6edb60807a3625667819b6d7a",
			policyFromTextpb(`
and { policy { rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } } } }
			`),
		},
		{
			"two unnecessary ANDs",
			"e0897fdc351b072a0abefd9aff51d75634755ee6edb60807a3625667819b6d7a",
			policyFromTextpb(`
and { policy { and { policy { rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } } } } } }
			`),
		},
		{
			"unnecessary OR",
			"e0897fdc351b072a0abefd9aff51d75634755ee6edb60807a3625667819b6d7a",
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
		Spams: map[uint16]helpers.SpamContents{
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
		{
			"unsatisfiable EQ",
			-1,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: EQ operand: "\x00\x01\x02\x04" }
					`),
				},
			},
		},
		{
			"unsatisfiable then satisfiable",
			1,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: EQ operand: "\x00\x01\x02\x04" }
					`),
				},
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: EQ operand: "\x00\x01\x02\x03" }
					`),
				},
			},
		},
		{
			"unsatisfiable NEQ",
			-1,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: NEQ operand: "\x00\x01\x02\x03" }
					`),
				},
			},
		},
		{
			"unsatisfiable GT",
			-1,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: GT operand: "\x00\x01\x02\x03" }
					`),
				},
			},
		},
		{
			"unsatisfiable LT",
			-1,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: LT operand: "\x00\x01\x02\x03" }
					`),
				},
			},
		},
		{
			"unsatisfiable GTE",
			-1,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: GTE operand: "\x00\x01\x02\x04" }
					`),
				},
			},
		},
		{
			"unsatisfiable LTE",
			-1,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: LTE operand: "\x00\x01\x02\x02" }
					`),
				},
			},
		},
		{
			"unsatisfiable BITSET",
			-1,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: BITSET operand: "\x00\x00\x02\x05" }
					`),
				},
			},
		},
		{
			"unsatisfiable BITCLEAR",
			-1,
			[][]*policypb.Rule{
				{
					ruleFromTextpb(`
spam { index: 1 offset: 0 comparison: BITCLEAR operand: "\xFF\x00\x01\x01" }
					`),
				},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			idx, err := helpers.FirstSatisfiable(testCase.rules, &tpmState)
			wantedErr := testCase.index < 0
			if !wantedErr && err != nil {
				t.Errorf("got error from FirstSatisfiable: %v", err)
			} else if wantedErr && err == nil {
				t.Errorf("wanted error from FirstSatisfiable, got %d, nil", *idx)
			} else if !wantedErr && err == nil {
				if *idx != testCase.index {
					t.Errorf("want %v got %v", testCase.index, *idx)
				}
			}
		})
	}
}

func startTrialSession(tpm io.ReadWriter) (*tpmutil.Handle, error) {
	handle, _, err := tpm2.StartAuthSession(
		tpm,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionTrial,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return nil, err
	}
	return &handle, nil
}

func TestRuleHashing(t *testing.T) {
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator")
	}
	defer tpm.Close()

	// Reference simulator is limited to 6 spams.
	// Since writing a spam changes its name, write randomly to them all.
	// Writing random data asserts that the actual contents (other than
	// nvWritten state) do not matter to the policy.
	for i := uint16(1); i <= 6; i++ {
		if err := spam.Define(tpm, i, ""); err != nil {
			t.Fatalf("could not define test spams: %v", err)
		}
		defer spam.Undefine(tpm, i, "")
		data := [64]byte{}
		if _, err := rand.Read(data[:]); err != nil {
			t.Fatalf("could not generate random data: %v", err)
		}
		if err := spam.Write(tpm, i, data); err != nil {
			t.Fatalf("could not write test spam: %v", err)
		}
	}

	cases := []struct {
		name  string
		rules []*policypb.Rule
	}{
		{
			"EQ",
			[]*policypb.Rule{
				ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: EQ operand: "frumious" }
				`),
			},
		},
		{
			"NEQ",
			[]*policypb.Rule{
				ruleFromTextpb(`
spam { index: 2 offset: 2 comparison: NEQ operand: "bandersnatch" }
				`),
			},
		},
		{
			"GT",
			[]*policypb.Rule{
				ruleFromTextpb(`
spam { index: 3 offset: 3 comparison: GT operand: "\x03" }
				`),
			},
		},
		{
			"GTE",
			[]*policypb.Rule{
				ruleFromTextpb(`
spam { index: 4 offset: 4 comparison: GTE operand: "\x03\x00" }
				`),
			},
		},
		{
			"LT",
			[]*policypb.Rule{
				ruleFromTextpb(`
spam { index: 5 offset: 5 comparison: LT operand: "\xff\xff\xff" }
				`),
			},
		},
		{
			"LTE",
			[]*policypb.Rule{
				ruleFromTextpb(`
spam { index: 6 offset: 6 comparison: LTE operand: "\xff\xff\xff\xee" }
				`),
			},
		},
		{
			"BITSET",
			[]*policypb.Rule{
				ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: BITSET operand: "\x01\x01" }
				`),
			},
		},
		{
			"BITCLEAR",
			[]*policypb.Rule{
				ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: BITCLEAR operand: "\xa0\xa0" }
				`),
			},
		},
		{
			"one of everything",
			[]*policypb.Rule{
				ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: EQ operand: "frumious" }
				`),
				ruleFromTextpb(`
spam { index: 2 offset: 2 comparison: NEQ operand: "bandersnatch" }
				`),
				ruleFromTextpb(`
spam { index: 3 offset: 3 comparison: GT operand: "\x03" }
				`),
				ruleFromTextpb(`
spam { index: 4 offset: 4 comparison: GTE operand: "\x03\x00" }
				`),
				ruleFromTextpb(`
spam { index: 5 offset: 5 comparison: LT operand: "\xff\xff\xff" }
				`),
				ruleFromTextpb(`
spam { index: 6 offset: 6 comparison: LTE operand: "\xff\xff\xff\xee" }
				`),
				ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: BITSET operand: "\x01\x01" }
				`),
				ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: BITCLEAR operand: "\xa0\xa0" }
				`),
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			sess, err := startTrialSession(tpm)
			if err != nil {
				t.Fatalf("could not start trial session: %v", err)
			}
			defer tpm2.FlushContext(tpm, *sess)
			calcHash := make([]byte, 32)
			for i, rule := range testCase.rules {
				err = helpers.RunRule(tpm, *sess, rule)
				if err != nil {
					t.Fatalf("could not run policy command: %v", err)
				}
				calcHash, err = helpers.ExtendPolicy(crypto.SHA256, calcHash, rule)
				if err != nil {
					t.Fatalf("could not hash policy: %v", err)
				}
				actualHash, err := tpm2.PolicyGetDigest(tpm, *sess)
				if err != nil {
					t.Fatalf("could not get hash from TPM: %v", err)
				}
				if !bytes.Equal(calcHash, actualHash) {
					t.Errorf("after rule %d, hash is incorrect\n"+
						"calculated: %s\nactual: %s\n", i,
						hex.EncodeToString(calcHash),
						hex.EncodeToString(actualHash))
					break
				}
			}
		})
	}
}

func TestOrHashing(t *testing.T) {
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer tpm.Close()

	// Reference simulator is limited to 6 spams.
	// Since writing a spam changes its name, write randomly to them all.
	// Writing random data asserts that the actual contents (other than
	// nvWritten state) do not matter to the policy.
	for i := uint16(1); i <= 6; i++ {
		if err := spam.Define(tpm, i, ""); err != nil {
			t.Fatalf("could not define test spams: %v", err)
		}
		defer spam.Undefine(tpm, i, "")
		data := [64]byte{}
		if _, err := rand.Read(data[:]); err != nil {
			t.Fatalf("could not generate random data: %v", err)
		}
		if err := spam.Write(tpm, i, data); err != nil {
			t.Fatalf("could not write test spam: %v", err)
		}
	}

	// Instead of having a bunch of test cases here, share a large list of rules
	// among all the tests.
	leaves := [][]*policypb.Rule{
		{
			ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: EQ operand: "frumious" }
			`),
		},
		{
			ruleFromTextpb(`
spam { index: 2 offset: 2 comparison: NEQ operand: "bandersnatch" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 3 offset: 3 comparison: GT operand: "\x03" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 4 offset: 4 comparison: GTE operand: "\x03\x00" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 5 offset: 5 comparison: LT operand: "\xff\xff\xff" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 6 offset: 6 comparison: LTE operand: "\xff\xff\xff\xee" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: BITSET operand: "\x01\x01" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: BITCLEAR operand: "\xa0\xa0" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: EQ operand: "frumious" }
				`),
			ruleFromTextpb(`
spam { index: 2 offset: 2 comparison: NEQ operand: "bandersnatch" }
				`),
			ruleFromTextpb(`
spam { index: 3 offset: 3 comparison: GT operand: "\x03" }
				`),
			ruleFromTextpb(`
spam { index: 4 offset: 4 comparison: GTE operand: "\x03\x00" }
				`),
			ruleFromTextpb(`
spam { index: 5 offset: 5 comparison: LT operand: "\xff\xff\xff" }
				`),
			ruleFromTextpb(`
spam { index: 6 offset: 6 comparison: LTE operand: "\xff\xff\xff\xee" }
				`),
			ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: BITSET operand: "\x01\x01" }
				`),
			ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: BITCLEAR operand: "\xa0\xa0" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 3 offset: 0 comparison: EQ operand: "foo" }
				`),
			ruleFromTextpb(`
spam { index: 3 offset: 3 comparison: NEQ operand: "bar" }
				`),
			ruleFromTextpb(`
spam { index: 3 offset: 6 comparison: NEQ operand: "baz" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: LTE operand: "\xff" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 2 offset: 2 comparison: LTE operand: "\xff" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 4 offset: 3 comparison: LTE operand: "\xff" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 5 offset: 5 comparison: LTE operand: "\xff" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 6 offset: 6 comparison: LTE operand: "\xff" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 1 offset: 1 comparison: LTE operand: "\xff" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 2 offset: 2 comparison: LTE operand: "\xff" }
				`),
		},
		{
			ruleFromTextpb(`
spam { index: 3 offset: 3 comparison: LTE operand: "\xff" }
				`),
		},
	}

	// Assemble a policy tree of each possible size (up to all the rules above),
	// then walk from each leaf all the way to the root and check that we agree
	// with the TPM's hash.
	for size := 2; size < len(leaves); size++ {
		policy := helpers.NormalizedPolicy(leaves[:size])
		tree, err := policy.CalculateTree(crypto.SHA256)
		if err != nil {
			t.Fatalf("error from CalculateTree: %v", err)
		}
		for startLeaf := 0; startLeaf < len(policy); startLeaf++ {
			t.Run(fmt.Sprintf("start-at-%d-of-%d", startLeaf, size), func(t *testing.T) {
				sess, err := startTrialSession(tpm)
				if err != nil {
					t.Fatalf("could not start trial session: %v", err)
				}
				defer tpm2.FlushContext(tpm, *sess)

				// Walk the tree from each leaf to the root and verify hashes.
				node, err := tree.LeafIndex(startLeaf)
				if err != nil {
					t.Fatalf("could not find leaf index %d: %v", startLeaf, err)
				}

				for *node != 0 {
					if err := helpers.RunOr(tpm, *sess, tree, *node); err != nil {
						t.Fatalf("RunOr: %v", err)
					}
					*node = eighttree.ParentIndex(*node)
					digest, err := tpm2.PolicyGetDigest(tpm, *sess)
					if err != nil {
						t.Fatalf("PolicyGetDigest: %v", err)
					}
					if !bytes.Equal(digest, tree[*node]) {
						t.Errorf("for node %d want:\n%s\ngot:\n%s\n",
							*node,
							hex.EncodeToString(digest),
							hex.EncodeToString(tree[*node]))
					}
				}
			})
		}
	}
}

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

	state, err := helpers.CurrentTpmState(tpm)
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
