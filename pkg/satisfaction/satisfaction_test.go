package satisfaction_test

import (
	"testing"

	"github.com/chrisfenner/tpm-spam/pkg/normpolicy"
	"github.com/chrisfenner/tpm-spam/pkg/policy"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/chrisfenner/tpm-spam/pkg/satisfaction"
	"github.com/chrisfenner/tpm-spam/pkg/tpmstate"
)

// Test a bunch of policies that should all be satisfied with the same simple state.
func TestSatisfiablePolicies(t *testing.T) {
	tpmState := tpmstate.TpmState{
		Spams: map[uint16]tpmstate.SpamContents{
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
		rules normpolicy.NormalizedPolicy
	}{
		{
			"simple EQ",
			0,
			[][]*policypb.Rule{
				{
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 0 comparison: EQ operand: "\x00\x01\x02\x04" }
					`),
				},
				{
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 0 comparison: BITCLEAR operand: "\xFF\x00\x01\x01" }
					`),
				},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			idx, err := satisfaction.FirstSatisfiable(testCase.rules, &tpmState)
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
