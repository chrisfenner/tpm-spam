package policy_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"
	"github.com/google/go-tpm-tools/simulator"

	"github.com/chrisfenner/tpm-spam/pkg/policy"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/chrisfenner/tpm-spam/pkg/spam"
)

func init() {
	rand.Seed(time.Now().UnixNano())
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
			policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 32 comparison: EQ operand: "foo" }
			`),
		},
		{
			"neq",
			"18d46f2acbf4519f6f0efb1ac6f58967a565d4c6fa53516e7597066fe2f0716a",
			policy.RuleFromTextpbOrPanic(`
spam { index: 2 offset: 4 comparison: NEQ operand: "bar" }
			`),
		},
		{
			"gt",
			"d1c47217845f7e69fc9edf2fa3b6a91cc78c3df98b40eb9bd37f742ecea53d8d",
			policy.RuleFromTextpbOrPanic(`
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
			policy, err := policy.Extend(crypto.SHA256, currentPolicy, testCase.rule)
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
				policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: EQ operand: "frumious" }
				`),
			},
		},
		{
			"NEQ",
			[]*policypb.Rule{
				policy.RuleFromTextpbOrPanic(`
spam { index: 2 offset: 2 comparison: NEQ operand: "bandersnatch" }
				`),
			},
		},
		{
			"GT",
			[]*policypb.Rule{
				policy.RuleFromTextpbOrPanic(`
spam { index: 3 offset: 3 comparison: GT operand: "\x03" }
				`),
			},
		},
		{
			"GTE",
			[]*policypb.Rule{
				policy.RuleFromTextpbOrPanic(`
spam { index: 4 offset: 4 comparison: GTE operand: "\x03\x00" }
				`),
			},
		},
		{
			"LT",
			[]*policypb.Rule{
				policy.RuleFromTextpbOrPanic(`
spam { index: 5 offset: 5 comparison: LT operand: "\xff\xff\xff" }
				`),
			},
		},
		{
			"LTE",
			[]*policypb.Rule{
				policy.RuleFromTextpbOrPanic(`
spam { index: 6 offset: 6 comparison: LTE operand: "\xff\xff\xff\xee" }
				`),
			},
		},
		{
			"BITSET",
			[]*policypb.Rule{
				policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: BITSET operand: "\x01\x01" }
				`),
			},
		},
		{
			"BITCLEAR",
			[]*policypb.Rule{
				policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: BITCLEAR operand: "\xa0\xa0" }
				`),
			},
		},
		{
			"one of everything",
			[]*policypb.Rule{
				policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: EQ operand: "frumious" }
				`),
				policy.RuleFromTextpbOrPanic(`
spam { index: 2 offset: 2 comparison: NEQ operand: "bandersnatch" }
				`),
				policy.RuleFromTextpbOrPanic(`
spam { index: 3 offset: 3 comparison: GT operand: "\x03" }
				`),
				policy.RuleFromTextpbOrPanic(`
spam { index: 4 offset: 4 comparison: GTE operand: "\x03\x00" }
				`),
				policy.RuleFromTextpbOrPanic(`
spam { index: 5 offset: 5 comparison: LT operand: "\xff\xff\xff" }
				`),
				policy.RuleFromTextpbOrPanic(`
spam { index: 6 offset: 6 comparison: LTE operand: "\xff\xff\xff\xee" }
				`),
				policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: BITSET operand: "\x01\x01" }
				`),
				policy.RuleFromTextpbOrPanic(`
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
				err = policy.RunRule(tpm, *sess, rule)
				if err != nil {
					t.Fatalf("could not run policy command: %v", err)
				}
				calcHash, err = policy.Extend(crypto.SHA256, calcHash, rule)
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
