// package normpolicy provides normalization functions for spam policy proto trees.
package normpolicy

import (
	"crypto"
	"fmt"

	"github.com/chrisfenner/tpm-spam/pkg/hashtree"
	"github.com/chrisfenner/tpm-spam/pkg/policy"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
)

// NormalizedPolicy represents the normalized OR/AND list-of-lists form of a policy.
type NormalizedPolicy [][]*policypb.Rule

// Normalize simplifies the policy tree (arbitrary AND/OR tree) into OR/AND list-of-lists form.
// This function returns the equivalent policy as a list of list of Rules.
// Each sublist of rules is a valid configuration, where all rules are ANDed together.
// The outer list is an OR-aggregation of all valid configurations.
// This is required because TPM2_PolicyOr checks that the current Policy hash is one of the
// permitted policies, then replaces the current Policy hash with the hash of all permitted values.
// A policy like PolicyFoo AND (PolicyBar OR PolicyBaz) could not be executed in the order:
// (PolicyFoo, PolicyBar, PolicyOR), because the running Policy hash would never consist of just
// PolicyBar (or PolicyBaz) - it would be based on PolicyFoo being executed before that.
// This policy must be rearranged as one of the following:
// 1. (PolicyFoo AND PolicyBar) OR (PolicyFoo AND PolicyBaz)
// 2. (PolicyBar OR PolicyBaz) AND PolicyFoo.
// This function rearranges to (1).
// (2) requires an even more complex "normal form" of "OR/AND list-of-lists followed by extra
// sequence of shared AND-rules" and does not reduce the number of ORed-together branches or the
// length of the executed policy.
func Normalize(policy *policypb.Policy) (NormalizedPolicy, error) {
	switch x := policy.Assertion.(type) {
	case *policypb.Policy_Rule:
		return normalizeRule(x.Rule)
	case *policypb.Policy_And:
		return normalizeAnd(x.And)
	case *policypb.Policy_Or:
		return normalizeOr(x.Or)
	}
	return nil, fmt.Errorf("unrecognized policy type: %v", policy.Assertion)
}

func normalizeRule(rule *policypb.Rule) ([][]*policypb.Rule, error) {
	// a single Rule is equivalent to a one-branch OR with just the one rule in the one branch.
	return [][]*policypb.Rule{{rule}}, nil
}

func normalizeAnd(and *policypb.And) ([][]*policypb.Rule, error) {
	if len(and.Policy) == 0 {
		return nil, fmt.Errorf("invalid AND: no subpolicies")
	}
	res, err := Normalize(and.Policy[0])
	// the normal form of an AND rule is the Cartesian product of the normalized sub-policies.
	if err != nil {
		return nil, fmt.Errorf("invalid AND: invalid subpolicy 0: %w", err)
	}
	for i, policy := range and.Policy[1:] {
		normalized, err := Normalize(policy)
		if err != nil {
			return nil, fmt.Errorf("invalid AND: invalid subpolicy %d: %w", i, err)
		}
		// Calculate the Cartesian product of the running policy with the next policy.
		// TODO: Reduce the number of reallocations here.
		var newRes [][]*policypb.Rule
		for _, originalPolicy := range res {
			for _, nextPolicy := range normalized {
				newRes = append(newRes, append(originalPolicy, nextPolicy...))
			}
		}
		res = newRes
	}
	return res, nil
}

func normalizeOr(or *policypb.Or) ([][]*policypb.Rule, error) {
	if len(or.Policy) == 0 {
		return nil, fmt.Errorf("invalid OR: no subpolicies")
	}
	// the normal form of an OR rule is the concatenation of the normalized sub-policies.
	var res [][]*policypb.Rule
	for i, policy := range or.Policy {
		normalized, err := Normalize(policy)
		if err != nil {
			return nil, fmt.Errorf("invalid OR: invalid subpolicy %d: %w", i, err)
		}
		res = append(res, normalized...)
	}
	return res, nil
}

// CalculateTree calculates the PolicyHashTree corresponding to a given NormalizedPolicy, using the
// given hash algorithm as the policy hash algorithm.
func (norm NormalizedPolicy) CalculateTree(alg crypto.Hash) (*hashtree.PolicyHashTree, error) {
	leaves := make([][]byte, len(norm))
	for i := range leaves {
		var err error
		leaves[i], err = policy.For(alg, norm[i])
		if err != nil {
			return nil, fmt.Errorf("failed to calculate leaf policy %d: %w", i, err)
		}
	}
	return hashtree.Build(alg, leaves)
}
