package normpolicy_test

import (
	"testing"

	"github.com/chrisfenner/tpm-spam/pkg/normpolicy"
	"github.com/chrisfenner/tpm-spam/pkg/policy"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/golang/protobuf/proto"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		name   string
		policy *policypb.Policy
		normal [][]*policypb.Rule
	}{
		{
			"and of two ors",
			policy.FromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 32 comparison: EQ operand: "foo" }
					`),
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 36 comparison: EQ operand: "baz" }
					`),
				},
				{
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 32 comparison: EQ operand: "foo" }
					`),
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 36 comparison: EQ operand: "qux" }
					`),
				},
				{
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 32 comparison: EQ operand: "bar" }
					`),
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 36 comparison: EQ operand: "baz" }
					`),
				},
				{
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 32 comparison: EQ operand: "bar" }
					`),
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 36 comparison: EQ operand: "qux" }
					`),
				},
			},
		},
		{
			"or of two ands",
			policy.FromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 32 comparison: EQ operand: "foo" }
					`),
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 36 comparison: EQ operand: "baz" }
					`),
				},
				{
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 32 comparison: EQ operand: "bar" }
					`),
					policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 36 comparison: EQ operand: "qux" }
					`),
				},
			},
		},
		{
			"and/or/and",
			policy.FromTextpbOrPanic(`
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
					policy.RuleFromTextpbOrPanic(` spam { operand: "a" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "b" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "e" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "f" } `),
				},
				{
					policy.RuleFromTextpbOrPanic(` spam { operand: "a" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "b" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "g" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "h" } `),
				},
				{
					policy.RuleFromTextpbOrPanic(` spam { operand: "c" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "d" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "e" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "f" } `),
				},
				{
					policy.RuleFromTextpbOrPanic(` spam { operand: "c" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "d" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "g" } `),
					policy.RuleFromTextpbOrPanic(` spam { operand: "h" } `),
				},
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			normalized, err := normpolicy.Normalize(testCase.policy)
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
