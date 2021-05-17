// package yaml provides mechanisms for serializing and deserializing spam
// policies in YAML.
//
// spam uses protocol buffers as the canonical format for several reasons:
// * Most invalid states are impossible to represent. For example, proto has sum
// types, while Go does not.
// * Efficient wire format for transmission and storage.
// * The protocol buffer compiler writes all the risky parsing code.
//
// That being said, for human consumption, textproto spam policies leave a bit
// to be desired.
//
// YAML is a JSON-based text serialization format that has human readability as
// its top priority.
//
// For very complex policies, the `define` key may be used to set up anchors
// that can be referred to later, in the actual policy. See the below example.
package yaml

import (
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/chrisfenner/tpm-spam/pkg/policypb"
)

// INTERNAL: Only exported for manipulation by the `yaml` package.
type Policy struct {
	And  []*Policy   `yaml:",omitempty"`
	Or   []*Policy   `yaml:",omitempty"`
	Spam *SpamPolicy `yaml:",flow,omitempty"`
	// Define is ignored when assembling policies: use it to define anchors for readability.
	Define []interface{}
}

// INTERNAL: Only exported for manipulation by the `yaml` package.
type SpamPolicy struct {
	Index    uint32
	Offset   uint32
	Eq       string `yaml:",omitempty"`
	Neq      string `yaml:",omitempty"`
	Gt       string `yaml:",omitempty"`
	Gte      string `yaml:",omitempty"`
	Lt       string `yaml:",omitempty"`
	Lte      string `yaml:",omitempty"`
	Bitset   string `yaml:",omitempty"`
	Bitclear string `yaml:",omitempty"`
}

// validate checks that policy data from a YAML document is a valid policy.
func (p *Policy) validate() error {
	if p == nil {
		return fmt.Errorf("invalid: nil policy")
	}
	pop := 0
	if len(p.And) != 0 {
		pop++
		for _, i := range p.And {
			if err := i.validate(); err != nil {
				return err
			}
		}
	}
	if len(p.Or) != 0 {
		pop++
		for _, i := range p.Or {
			if err := i.validate(); err != nil {
				return err
			}
		}
	}
	if p.Spam != nil {
		pop++
		if err := p.Spam.validate(); err != nil {
			return err
		}
	}
	if pop != 1 {
		return fmt.Errorf("exactly one of (and, or, spam) required for policy node")
	}
	return nil
}

// validate checks that policy data from a YAML document is a valid spam policy.
func (p *SpamPolicy) validate() error {
	if p == nil {
		return fmt.Errorf("invalid: nil policy")
	}
	if p.Index < 0 || p.Index > math.MaxUint16 {
		return fmt.Errorf("invalid index: %d", p.Index)
	}
	if p.Offset < 0 || p.Offset >= 64 {
		return fmt.Errorf("invalid offset: %d", p.Offset)
	}
	var operand *string
	pop := 0
	if p.Eq != "" {
		pop++
		operand = &p.Eq
	}
	if p.Neq != "" {
		pop++
		operand = &p.Neq
	}
	if p.Gt != "" {
		pop++
		operand = &p.Gt
	}
	if p.Gte != "" {
		pop++
		operand = &p.Gte
	}
	if p.Lt != "" {
		pop++
		operand = &p.Lt
	}
	if p.Lte != "" {
		pop++
		operand = &p.Lte
	}
	if p.Bitset != "" {
		pop++
		operand = &p.Bitset
	}
	if p.Bitclear != "" {
		pop++
		operand = &p.Bitclear
	}
	if pop != 1 {
		return fmt.Errorf("exactly one of (eq, neq, gt, gte, lt, lte, bitset, bitclear) required for spam policy node")
	}
	data, err := dataFromOperand(*operand)
	if err != nil {
		return err
	}
	opLength := uint32(len(data))
	if opLength+p.Offset > 64 {
		return fmt.Errorf("offset (%d) + operand length (%d) must be less than or equal to 64", p.Offset, opLength)
	}
	return nil
}

// dataFromOperand decodes a hex string, which must be of the form "0x..."
func dataFromOperand(op string) ([]byte, error) {
	if len(op) < 4 || strings.ToLower(op[:2]) != "0x" {
		return nil, fmt.Errorf("operand must be 0x followed by a hex string of at least 1 byte")
	}
	data, err := hex.DecodeString(op[2:])
	if err != nil {
		return nil, fmt.Errorf("could not decode hex operand: %w", err)
	}
	return data, nil
}

// proto converts a Policy into the canonical protobuf form.
func (p *Policy) proto() (*policypb.Policy, error) {
	var result policypb.Policy

	if len(p.And) != 0 {
		pols := make([]*policypb.Policy, 0, len(p.And))
		for _, pol := range p.And {
			pol, err := pol.proto()
			if err != nil {
				return nil, err
			}
			pols = append(pols, pol)
		}
		result.Assertion = &policypb.Policy_And{
			And: &policypb.And{
				Policy: pols,
			},
		}
	} else if len(p.Or) != 0 {
		pols := make([]*policypb.Policy, 0, len(p.Or))
		for _, pol := range p.Or {
			pol, err := pol.proto()
			if err != nil {
				return nil, err
			}
			pols = append(pols, pol)
		}
		result.Assertion = &policypb.Policy_Or{
			Or: &policypb.Or{
				Policy: pols,
			},
		}
	} else if p.Spam != nil {
		rule, err := p.Spam.proto()
		if err != nil {
			return nil, err
		}
		result.Assertion = &policypb.Policy_Rule{
			Rule: &policypb.Rule{
				Assertion: &policypb.Rule_Spam{
					Spam: rule,
				},
			},
		}
	}

	return &result, nil
}

// proto converts a SpamPolicy into the canonical protobuf form.
func (p *SpamPolicy) proto() (*policypb.SpamRule, error) {
	var comparison policypb.Comparison
	var operand *string
	switch {
	case p.Eq != "":
		comparison = policypb.Comparison_EQ
		operand = &p.Eq
	case p.Neq != "":
		comparison = policypb.Comparison_NEQ
		operand = &p.Neq
	case p.Gt != "":
		comparison = policypb.Comparison_GT
		operand = &p.Gt
	case p.Gte != "":
		comparison = policypb.Comparison_GTE
		operand = &p.Gte
	case p.Lt != "":
		comparison = policypb.Comparison_LT
		operand = &p.Lt
	case p.Lte != "":
		comparison = policypb.Comparison_LTE
		operand = &p.Lte
	case p.Bitset != "":
		comparison = policypb.Comparison_BITSET
		operand = &p.Bitset
	case p.Bitclear != "":
		comparison = policypb.Comparison_BITCLEAR
		operand = &p.Bitclear
	default:
		return nil, fmt.Errorf("unrecognized comparison for spam policy: %+v", p)
	}

	operandData, err := dataFromOperand(*operand)
	if err != nil {
		return nil, fmt.Errorf("invalid operand for spam policy: %w", err)
	}

	return &policypb.SpamRule{
		Index:      p.Index,
		Offset:     p.Offset,
		Comparison: comparison,
		Operand:    operandData,
	}, nil
}

// fromProto converts from proto to internal ready-for-YAML policy form.
func fromProto(p *policypb.Policy) (*Policy, error) {
	switch x := p.Assertion.(type) {
	case *policypb.Policy_And:
		subPolicies := make([]*Policy, 0, len(x.And.Policy))
		for _, and := range x.And.Policy {
			subPolicy, err := fromProto(and)
			if err != nil {
				return nil, err
			}
			subPolicies = append(subPolicies, subPolicy)
		}
		return &Policy{
			And: subPolicies,
		}, nil
	case *policypb.Policy_Or:
		subPolicies := make([]*Policy, 0, len(x.Or.Policy))
		for _, or := range x.Or.Policy {
			subPolicy, err := fromProto(or)
			if err != nil {
				return nil, err
			}
			subPolicies = append(subPolicies, subPolicy)
		}
		return &Policy{
			Or: subPolicies,
		}, nil
	case *policypb.Policy_Rule:
		return fromRuleProto(x.Rule)
	default:
		return nil, fmt.Errorf("unknown policy node type: %v", reflect.TypeOf(p.Assertion))
	}
}

// fromProto converts from proto to internal ready-for-YAML rule form.
func fromRuleProto(r *policypb.Rule) (*Policy, error) {
	switch x := r.Assertion.(type) {
	case *policypb.Rule_Spam:
		return fromSpamRuleProto(x.Spam)
	default:
		return nil, fmt.Errorf("unrecognized rule type: %v", x)
	}
}

// fromProto converts from proto to internal ready-for-YAML spam rule form.
func fromSpamRuleProto(r *policypb.SpamRule) (*Policy, error) {
	result := SpamPolicy{
		Index:  r.Index,
		Offset: r.Offset,
	}
	hexOperand := "0x" + hex.EncodeToString(r.Operand)
	switch r.Comparison {
	case policypb.Comparison_EQ:
		result.Eq = hexOperand
	case policypb.Comparison_NEQ:
		result.Neq = hexOperand
	case policypb.Comparison_GT:
		result.Gt = hexOperand
	case policypb.Comparison_GTE:
		result.Gte = hexOperand
	case policypb.Comparison_LT:
		result.Lt = hexOperand
	case policypb.Comparison_LTE:
		result.Lte = hexOperand
	case policypb.Comparison_BITSET:
		result.Bitset = hexOperand
	case policypb.Comparison_BITCLEAR:
		result.Bitclear = hexOperand
	default:
		return nil, fmt.Errorf("unrecognized comparison '%v'", r.Comparison)
	}

	return &Policy{
		Spam: &result,
	}, nil
}

// Decode parses a YAML document for a spam policy, and converts it into the canonical protobuf form.
func Decode(s string) (*policypb.Policy, error) {
	var pol Policy
	if err := yaml.Unmarshal([]byte(s), &pol); err != nil {
		return nil, fmt.Errorf("could not unmarshal YAML policy: %w", err)
	}
	if err := pol.validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	return pol.proto()
}

// DecodeOrPanic parses a YAML document for a spam policy, or panics if there is an error.
func DecodeOrPanic(s string) *policypb.Policy {
	proto, err := Decode(s)
	if err != nil {
		panic(err)
	}
	return proto
}

// Encode converts a spam policy from the canonical protobuf form into more human-readable YAML form.
func Encode(p *policypb.Policy) (*string, error) {
	pol, err := fromProto(p)
	if err != nil {
		return nil, err
	}
	result, err := yaml.Marshal(pol)
	if err != nil {
		return nil, err
	}
	resultStr := string(result)
	return &resultStr, nil
}

// DebugString converts a spam policy into YAML or the error string from attempting to do so.
func DebugString(p *policypb.Policy) string {
	yaml, err := Encode(p)
	if err != nil {
		return err.Error()
	}
	return *yaml
}
