package satisfaction

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/chrisfenner/tpm-spam/pkg/normpolicy"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/chrisfenner/tpm-spam/pkg/tpmstate"
)

// FirstSatisfiable finds the index of the first satisfiable policy branch, or returns an error if no policy was satisfiable.
func FirstSatisfiable(policies normpolicy.NormalizedPolicy, currentState *tpmstate.TpmState) (*int, error) {
	for i, policy := range policies {
		satisfiable := true
		for _, rule := range policy {
			if !isSatisfiable(rule, currentState) {
				satisfiable = false
				break
			}
		}
		if satisfiable {
			return &i, nil
		}
	}
	return nil, fmt.Errorf("unsatisfiable spam policy")
}

// isSatisfiable returns whether a rule would pass if enforced by the TPM whose
// current state is described by currentState.
func isSatisfiable(rule *policypb.Rule, currentState *tpmstate.TpmState) bool {
	switch x := rule.Assertion.(type) {
	case *policypb.Rule_Spam:
		return isSpamSatisfiable(x.Spam, currentState)
	default:
		return false
	}
}

// isSpamSatisfiable returns whether a spam rule would pass if enforced by the
// TPM whose current state is described by currentState.
func isSpamSatisfiable(rule *policypb.SpamRule, currentState *tpmstate.TpmState) bool {
	if rule.Offset+uint32(len(rule.Operand)) > 64 {
		// not a valid policy
		return false
	}
	contents, ok := currentState.Spams[uint16(rule.Index)]
	if !ok {
		// The indicated spam is not written so it cannot be compared.
		// N.B.: If the indicated spam is defined but not written,
		// anybody could write anything to it and satisfy the policy.
		return false
	}
	spamOperand := contents[rule.Offset : rule.Offset+uint32(len(rule.Operand))]
	switch rule.Comparison {
	case policypb.Comparison_EQ:
		return isSpamEq(spamOperand, rule.Operand)
	case policypb.Comparison_NEQ:
		return isSpamNeq(spamOperand, rule.Operand)
	case policypb.Comparison_GT:
		return isSpamGt(spamOperand, rule.Operand)
	case policypb.Comparison_LT:
		return isSpamLt(spamOperand, rule.Operand)
	case policypb.Comparison_GTE:
		return isSpamGte(spamOperand, rule.Operand)
	case policypb.Comparison_LTE:
		return isSpamLte(spamOperand, rule.Operand)
	case policypb.Comparison_BITSET:
		return isSpamBitSet(spamOperand, rule.Operand)
	case policypb.Comparison_BITCLEAR:
		return isSpamBitClear(spamOperand, rule.Operand)
	}
	// Unrecognized comparison
	return false
}

func isSpamEq(a, b []byte) bool {
	return bytes.Equal(a, b)
}

func isSpamNeq(a, b []byte) bool {
	return !isSpamEq(a, b)
}

func isSpamGt(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	bigA := big.NewInt(0).SetBytes(a)
	bigB := big.NewInt(0).SetBytes(b)
	return bigA.Cmp(bigB) > 0
}

func isSpamLt(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	bigA := big.NewInt(0).SetBytes(a)
	bigB := big.NewInt(0).SetBytes(b)
	return bigA.Cmp(bigB) < 0
}

func isSpamGte(a, b []byte) bool {
	return !isSpamLt(a, b)
}

func isSpamLte(a, b []byte) bool {
	return !isSpamGt(a, b)
}

func isSpamBitSet(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	// BITSET: all bits set in B are set in A
	for i := range a {
		if (a[i] & b[i]) != b[i] {
			return false
		}
	}
	return true
}

func isSpamBitClear(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	// BITCLEAR: all bits set in B are clear in A
	for i := range a {
		if (a[i] & b[i]) != 0 {
			return false
		}
	}
	return true
}
