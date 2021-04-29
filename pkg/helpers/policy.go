package helpers

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"github.com/chrisfenner/tpm-spam/pkg/eighttree"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
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

func SpamPolicy(alg crypto.Hash) ([]byte, error) {
	result := make([]byte, alg.Size())
	return HashItems(alg, result, uint32(0x18f), uint8(0))
}

func SpamTemplate(index uint32) (*tpm2.NVPublic, error) {
	if index > 0xffff {
		return nil, fmt.Errorf("invalid spam index %d (must be a uint16)", index)
	}
	policy, err := SpamPolicy(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("could not calculate spam policy: %w", err)
	}
	// Attribute rationales:
	//   TPMA_NV_PPWRITE = 0: Can't write with Platform Authorization
	//   TPMA_NV_OWNERWRITE = 0: Can't write with Owner Authorization
	//   TPMA_NV_AUTHWRITE = 0: Can't write with Auth Value
	//   TPMA_NV_POLICYWRITE = 1: Can write with Policy
	//   TPMA_NV_POLICY_DELETE = 0: Can delete with Platform Authorization
	//   TPMA_NV_WRITELOCKED = 0: Not write locked (can't be set at creation)
	//   TPMA_NV_WRITEALL = 1: A partial write of the data is not allowed
	//   TPMA_NV_WRITEDEFINE = 0: May not be permanently write-locked
	//   TPMA_NV_WRITE_STCLEAR = 0: May not be write-locked until next boot
	//   TPMA_NV_GLOBALLOCK = 0: Is not affected by the global NV lock
	//   TPMA_NV_PPREAD = 0: Can't read with Platform Authorization
	//   TPMA_NV_OWNERREAD = 0: Can't read with Owner Authorization
	//   TPMA_NV_AUTHREAD = 1: Can read with Auth Value
	//   TPMA_NV_POLICYREAD = 0: Can't read with Policy
	//   TPMA_NV_NO_DA = 1: Exempt from Dictionary Attack logic
	//   TPMA_NV_ORDERLY = 1: Only required t obe saved when shut down
	//   TPMA_NV_CLEAR_STCLEAR = 1: TPMA_NV_WRITTEN is cleared by reboot
	//   TPMA_NV_READLOCKED = 0: Not read locked (can't be set at creation)
	//   TPMA_NV_WRITTEN = 0: Not already written (can't be set at creation)
	//   TPMA_NV_PLATFORMCREATE = 1: Undefined with Platform, not Owner Auth
	//   TPMA_NV_READ_STCLEAR = 0: May not be read-locked
	attr := tpm2.AttrPolicyWrite |
		tpm2.AttrWriteAll |
		tpm2.AttrAuthRead |
		tpm2.AttrNoDA |
		tpm2.AttrOrderly |
		tpm2.AttrClearSTClear |
		tpm2.AttrPlatformCreate
	return &tpm2.NVPublic{
		NVIndex:    tpmutil.Handle(0x017F0000 + index),
		NameAlg:    tpm2.AlgSHA256,
		Attributes: attr,
		AuthPolicy: tpmutil.U16Bytes(policy),
		DataSize:   64,
	}, nil
}

// spamName returns the TPM2B_NAME for a spam NV index.
func spamName(index uint32, alg crypto.Hash) ([]byte, error) {
	packed, err := tpmutil.Pack(SpamTemplate(index))
	if err != nil {
		return nil, err
	}
	hash, err := HashItems(alg, packed)
	if err != nil {
		return nil, err
	}
	tpmAlg, err := tpm2.HashToAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err = binary.Write(&buf, binary.BigEndian, tpmAlg); err != nil {
		return nil, err
	}
	if _, err = buf.Write(hash); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// extendSpamPolicy calculates the policy hash for a SpamRule (which is a type of TPM2_PolicyNV)
func extendSpamPolicy(currentPolicy []byte, rule *policypb.SpamRule, alg crypto.Hash) ([]byte, error) {
	args, err := HashItems(alg, rule.Operand, rule.Offset, uint16(rule.Comparison))
	if err != nil {
		return nil, fmt.Errorf("could not calculate args hash: %w", err)
	}
	name, err := spamName(rule.Index, alg)
	if err != nil {
		return nil, fmt.Errorf("could not calculate NV index name: %w", err)
	}
	return HashItems(alg, currentPolicy, alg, uint32(0x149), args, name)
}

// ExtendPolicy calculates the policy hash for a Rule, given a starting policy.
func ExtendPolicy(alg crypto.Hash, currentPolicy []byte, rule *policypb.Rule) ([]byte, error) {
	switch x := rule.Assertion.(type) {
	case *policypb.Rule_Spam:
		return extendSpamPolicy(currentPolicy, x.Spam, alg)
	default:
		return nil, fmt.Errorf("unrecognized rule type: %v", x)
	}
}

// leafPolicy calculates the TPM policy hash for the given sequence of leaf rules, with the
// specified algorithm, storing it into policy.
func leafPolicy(policy *[]byte, rules []*policypb.Rule, alg crypto.Hash) error {
	result := make([]byte, alg.Size())
	for i, rule := range rules {
		var err error
		result, err = ExtendPolicy(alg, result, rule)
		if err != nil {
			return fmt.Errorf("could not calculate rule %d policy hash: %w", i, err)
		}
	}
	*policy = result
	return nil
}

// policyChildren returns the digest of all the children of the given internal node. If the node is a leaf node, returns nil.
func policyChildren(t PolicyHashTree, index int) [][]byte {
	start := eighttree.ChildIndex(index, 0)
	if start >= len(t) {
		return nil
	}
	end := eighttree.ChildIndex(index, 7)
	if end > len(t) {
		end = len(t)
	}
	return t[start:end]
}

// internalPolicy calculates the TPM policy hash for the given internal node, with the specified
// algorithm, storing it into policy.
// This function works on partially calculated policy trees, but it requires that all nodes after
// the given node have already been calculated.
func internalPolicy(policy *[]byte, t PolicyHashTree, index int, alg crypto.Hash) error {
	children := policyChildren(t, index)
	result := make([]byte, alg.Size())
	result, err := HashItems(alg, result, uint32(0x171), children)
	if err != nil {
		return err
	}
	*policy = result
	return nil
}

// CalculatePolicy calculates the TPM policy hash associated with the given spam policy with the specified algorithm.
func CalculatePolicy(policy *policypb.Policy, alg crypto.Hash) ([]byte, error) {
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
