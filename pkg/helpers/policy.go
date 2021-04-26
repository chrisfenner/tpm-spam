package helpers

import (
	"crypto"
	"fmt"
	"github.com/chrisfenner/tpm-spam/pkg/eighttree"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
)

// NormalizedPolicy represents the normalized OR/AND list-of-lists form of a policy.
type NormalizedPolicy [][]*policypb.Rule

// PolicyHashTree represents a TPM2_PolicyOR tree for a NormalizedPolicy as a complete 8-tree, where
// all internal nodes are hashes of PolicyOR commands, and the nth leaf node is the hash of the nth
// normalized sublist's policy.
type PolicyHashTree [][]byte

// CalculateTree calculates the PolicyHashTree corresponding to a given NormalizedPolicy, using the
// given hash algorithm as the policy hash algorithm.
func (norm NormalizedPolicy) CalculateTree(alg crypto.Hash) (PolicyHashTree, error) {
	leafCount := len(norm)
	internalCount := eighttree.InternalCountFromLeaves(leafCount)
	result := make(PolicyHashTree, internalCount+leafCount)

	for i, policy := range norm {
		leaf, err := result.leaf(i)
		if err != nil {
			return nil, fmt.Errorf("failed to get leaf %d: %w", i, err)
		}
		if err := leafPolicy(leaf, policy, alg); err != nil {
			return nil, fmt.Errorf("failed to calculate leaf policy %d: %w", i, err)
		}
	}

	for i := internalCount - 1; i >= 0; i-- {
		if err := internalPolicy(&result[i], result, i, alg); err != nil {
			return nil, fmt.Errorf("failed to calculate internal policy %d: %w", i, err)
		}
	}

	return result, nil
}

// leaf returns a pointer to the given leaf in the tree.
func (t PolicyHashTree) leaf(i int) (*[]byte, error) {
	internal, err := eighttree.InternalCountFromTotal(len(t))
	if err != nil {
		return nil, fmt.Errorf("invalid tree: %w", err)
	}
	if (internal + i) >= len(t) {
		return nil, fmt.Errorf("policy tree does not have %d leaves", i)
	}
	return &t[internal+i], nil
}

// leafPolicy calculates the TPM policy hash for the given sequence of leaf rules, with the
// specified algorithm, storing it into policy.
func leafPolicy(policy *[]byte, rules []*policypb.Rule, alg crypto.Hash) error {
	// TODO: calculate the policy hash of all the rules according to the TPM specification.
	return nil
}

// internalPolicy calculates the TPM policy hash for the given internal node, with the specified
// algorithm, storing it into policy.
// This function works on partially calculated policy trees, but it requires that all nodes after
// the given node have already been calculated.
func internalPolicy(policy *[]byte, t PolicyHashTree, index int, alg crypto.Hash) error {
	// TODO: calculate the PolicyOR of all the children according to the TPM specification.
	return nil
}

// Calculate the TPM policy hash associated with the given spam policy with the specified algorithm.
func Calculate(policy *policypb.Policy, alg crypto.Hash) ([]byte, error) {
	norm, err := Normalize(policy)
	if err != nil {
		return nil, fmt.Errorf("could not normalize policy: %w", err)
	}
	tree, err := norm.CalculateTree(alg)
	if err != nil {
		return nil, fmt.Errorf("could not build policyOR tree: %w", err)
	}
	return tree[0], nil
}

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
