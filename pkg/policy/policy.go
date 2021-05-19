// package policy provides helpers for running the TPM2 policy rules
// corresponding to spam policy checks.
package policy

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"
	"google.golang.org/protobuf/encoding/prototext"

	"github.com/chrisfenner/tpm-spam/pkg/behash"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/chrisfenner/tpm-spam/pkg/spamdef"
)

// InvalidPolicyError indicates that something is wrong with a spam policy.
type InvalidPolicyError struct {
	Policy interface{}
	Err    error
}

func (e InvalidPolicyError) Error() string {
	return fmt.Sprintf("invalid policy: %v:\n%+v", e.Err, e.Policy)
}
func (e InvalidPolicyError) Unwrap() error {
	return e.Err
}

var (
	ErrInvalidType       = errors.New("invalid type")
	ErrInvalidIndex      = errors.New("invalid index")
	ErrInvalidComparison = errors.New("invalid comparison")
	ErrInvalidAssertion  = errors.New("invalid assertion")
	ErrNoSubpolicies     = errors.New("no subpolicies")
	ErrOverflow          = errors.New("offset + data length > 64")
	ErrNilPolicy         = errors.New("nil policy")
)

// For calculates the TPM policy hash for the given sequence of rules, with the specified algorithm.
func For(alg crypto.Hash, rules []*policypb.Rule) ([]byte, error) {
	result := make([]byte, alg.Size())
	for i, rule := range rules {
		var err error
		result, err = Extend(alg, result, rule)
		if err != nil {
			return nil, fmt.Errorf("could not calculate rule %d policy hash: %w", i, err)
		}
	}
	return result, nil
}

// Extend calculates the policy hash for a rule, given a starting policy, with the specified algorithm.
func Extend(alg crypto.Hash, currentPolicy []byte, rule *policypb.Rule) ([]byte, error) {
	switch x := rule.Assertion.(type) {
	case *policypb.Rule_Spam:
		return extendSpamPolicy(currentPolicy, x.Spam, alg)
	default:
		return nil, InvalidPolicyError{rule, ErrInvalidType}
	}
}

// RunRule runs the rule in the given session handle.
func RunRule(tpm io.ReadWriter, s tpmutil.Handle, r *policypb.Rule) error {
	switch x := r.Assertion.(type) {
	case *policypb.Rule_Spam:
		return spamPolicyRule(tpm, s, x.Spam)
	default:
		return InvalidPolicyError{r, ErrInvalidType}
	}
}

// extendSpamPolicy calculates the policy hash for a SpamRule (which is a type of TPM2_PolicyNV)
func extendSpamPolicy(currentPolicy []byte, rule *policypb.SpamRule, alg crypto.Hash) ([]byte, error) {
	if rule.Index > math.MaxUint16 {
		return nil, InvalidPolicyError{rule, ErrInvalidIndex}
	}
	operation, err := operation(rule.Comparison)
	if err != nil {
		return nil, InvalidPolicyError{rule, err}
	}

	args, err := behash.HashItems(alg, rule.Operand, uint16(rule.Offset), *operation)
	if err != nil {
		return nil, fmt.Errorf("could not calculate args hash: %w", err)
	}
	name, err := spamdef.Name(uint16(rule.Index))
	if err != nil {
		return nil, fmt.Errorf("could not calculate NV index name: %w", err)
	}

	return behash.HashItems(alg, currentPolicy, uint32(0x149), args, name)
}

func spamPolicyRule(tpm io.ReadWriter, s tpmutil.Handle, r *policypb.SpamRule) error {
	handle, err := spamdef.Handle(uint16(r.Index))
	if err != nil {
		return err
	}
	operand := tpmutil.U16Bytes(r.Operand)
	offset := uint16(r.Offset)
	if uint32(offset) != r.Offset || int(offset)+len(operand) > 64 {
		return InvalidPolicyError{r, ErrOverflow}
	}
	operation, err := operation(r.Comparison)
	if err != nil {
		return err
	}
	return tpm2.PolicyNV(tpm, *handle, *handle, s, "", operand, offset, *operation)
}

// operation returns the TPM_EO equivalent of the given spam comparison.
func operation(comp policypb.Comparison) (*tpm2.EO, error) {
	var result tpm2.EO
	switch comp {
	case policypb.Comparison_EQ:
		result = tpm2.EOEq
	case policypb.Comparison_NEQ:
		result = tpm2.EONeq
	case policypb.Comparison_GT:
		result = tpm2.EOUnsignedGt
	case policypb.Comparison_GTE:
		result = tpm2.EOUnsignedGe
	case policypb.Comparison_LT:
		result = tpm2.EOUnsignedLt
	case policypb.Comparison_LTE:
		result = tpm2.EOUnsignedLe
	case policypb.Comparison_BITSET:
		result = tpm2.EOBitSet
	case policypb.Comparison_BITCLEAR:
		result = tpm2.EOBitClear
	default:
		return nil, ErrInvalidComparison
	}
	return &result, nil
}

// FromTextpbOrPanic returns a Policy parsed from a given textpb.
func FromTextpbOrPanic(textpb string) *policypb.Policy {
	var policy policypb.Policy
	if err := prototext.Unmarshal([]byte(textpb), &policy); err != nil {
		panic(err)
	}
	return &policy
}

// RuleFromTextpbOrPanic returns a Rule parsed from a given textpb.
func RuleFromTextpbOrPanic(textpb string) *policypb.Rule {
	var rule policypb.Rule
	if err := prototext.Unmarshal([]byte(textpb), &rule); err != nil {
		panic(err)
	}
	return &rule
}
