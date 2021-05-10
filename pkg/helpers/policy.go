package helpers

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"
	"github.com/chrisfenner/tpm-spam/pkg/eighttree"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"io"
	"math"
	"math/big"
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
func (t PolicyHashTree) leafIndex(i int) (*int, error) {
	internal, err := eighttree.InternalCountFromTotal(len(t))
	if err != nil {
		return nil, fmt.Errorf("invalid tree: %w", err)
	}
	if (internal + i) >= len(t) {
		return nil, fmt.Errorf("policy tree does not have %d leaves", i)
	}
	result := internal + i
	return &result, nil
}
func (t PolicyHashTree) leaf(i int) (*[]byte, error) {
	idx, err := t.leafIndex(i)
	if err != nil {
		return nil, err
	}
	return &t[*idx], nil
}

func SpamPolicy(alg crypto.Hash) ([]byte, error) {
	result := make([]byte, alg.Size())
	return HashItems(alg, result, uint32(0x18f), uint8(0))
}

// SpamHandle returns the TPM NV index associated with the given spam handle.
func SpamHandle(index uint16) (*tpmutil.Handle, error) {
	if index > 0xffff {
		return nil, fmt.Errorf("invalid spam index %d (must be a uint16)", index)
	}
	result := tpmutil.Handle(0x017F0000 + uint32(index))
	return &result, nil
}

// SpamOperation returns the TPM_EO equivalent of the given spam comparison.
func SpamOperation(comp policypb.Comparison) (*tpm2.EO, error) {
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
		return nil, fmt.Errorf("invalid comparison %v", comp)
	}
	return &result, nil
}

func SpamTemplate(index uint16) (*tpm2.NVPublic, error) {
	handle, err := SpamHandle(index)
	if err != nil {
		return nil, err
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
		NVIndex:    *handle,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: attr,
		AuthPolicy: tpmutil.U16Bytes(policy),
		DataSize:   64,
	}, nil
}

// SpamName returns the name for a spam NV index.
func SpamName(index uint16) ([]byte, error) {
	alg := crypto.SHA256
	template, err := SpamTemplate(index)
	if err != nil {
		return nil, err
	}
	template.Attributes |= tpm2.AttrWritten
	packed, err := tpmutil.Pack(template)
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
	if rule.Index > math.MaxUint16 {
		return nil, fmt.Errorf("invalid spam index %d", rule.Index)
	}
	operation, err := SpamOperation(rule.Comparison)
	if err != nil {
		return nil, err
	}

	args, err := HashItems(alg, rule.Operand, uint16(rule.Offset), *operation)
	if err != nil {
		return nil, fmt.Errorf("could not calculate args hash: %w", err)
	}
	name, err := SpamName(uint16(rule.Index))
	if err != nil {
		return nil, fmt.Errorf("could not calculate NV index name: %w", err)
	}

	return HashItems(alg, currentPolicy, uint32(0x149), args, name)
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

// policyChildren returns the digests of all the children of the given internal node. If the node is a leaf node, returns nil.
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
	args := []interface{}{
		result, uint32(0x171),
	}
	// TODO: clean up this copy that gets around inability to cast [][]byte to []interface{}
	for _, child := range children {
		args = append(args, child)
	}
	result, err := HashItems(alg, args...)
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

// SpamContents represents the contents of a spam.
type SpamContents [64]byte

// TpmState represents the spam policy-relevant current state in the TPM.
type TpmState struct {
	Spams map[uint32]SpamContents
}

// CurrentTpmState queries the TPM for its current spam-relevant state.
// TODO: Clean up this function, it has a lot of magic numbers and casts.
func CurrentTpmState(tpm io.ReadWriter) (*TpmState, error) {
	spams := make(map[uint32]SpamContents)
	for handle := uint32(0x017F0000); handle < uint32(0x01800000); handle++ {
		handles, _, err := tpm2.GetCapability(tpm, tpm2.CapabilityHandles, 8, handle)
		if err != nil {
			return nil, err
		}
		for _, h := range handles {
			hdl, ok := h.(tpmutil.Handle)
			if !ok {
				return nil, fmt.Errorf("invalid data from GetCapability: %v", h)
			}
			if uint32(hdl) > handle {
				handle = uint32(hdl)
			}
			if uint32(hdl) >= uint32(0x01800000) {
				continue
			}
			data, err := tpm2.NVReadEx(tpm, hdl, hdl, "", 64)
			if err != nil || len(data) != 64 {
				// Don't worry about this one
				continue
			}
			spamIndex := uint32(hdl) - uint32(0x017F0000)
			var spam SpamContents
			copy(spam[:], data)
			spams[spamIndex] = spam
		}
	}
	return &TpmState{
		Spams: spams,
	}, nil
}

// FirstSatisfiable finds the index of the first satisfiable policy branch, or
// returns an error if no policy was satisfiable.
func FirstSatisfiable(policies NormalizedPolicy, currentState *TpmState) (*int, error) {
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

func spamPolicyRule(tpm io.ReadWriter, s tpmutil.Handle, r *policypb.SpamRule) error {
	handle, err := SpamHandle(uint16(r.Index))
	if err != nil {
		return err
	}
	operand := tpmutil.U16Bytes(r.Operand)
	offset := uint16(r.Offset)
	if uint32(offset) != r.Offset {
		return fmt.Errorf("invalid offset: %v", r.Offset)
	}
	if int(offset)+len(operand) > 64 {
		return fmt.Errorf("invalid offset and operand length: %v bytes starting at %v", len(operand), r.Offset)
	}
	operation, err := SpamOperation(r.Comparison)
	if err != nil {
		return err
	}
	return tpm2.PolicyNV(tpm, *handle, *handle, s, "", operand, offset, *operation)
}

// RunRule runs the rule in the given session handle.
func RunRule(tpm io.ReadWriter, s tpmutil.Handle, r *policypb.Rule) error {
	switch x := r.Assertion.(type) {
	case *policypb.Rule_Spam:
		return spamPolicyRule(tpm, s, x.Spam)
	default:
		return fmt.Errorf("unrecognized rule type: %v", x)
	}
}

// RunOr runs the PolicyOr command to go from the given node to its parent, in
// the given session handle.
func RunOr(tpm io.ReadWriter, s tpmutil.Handle, tree PolicyHashTree, index int) error {
	if index <= 0 {
		return fmt.Errorf("specified node %d has no parent", index)
	}
	if index >= len(tree) {
		return fmt.Errorf("specified node %d does not exist", index)
	}
	parent := eighttree.ParentIndex(index)
	ors := policyChildren(tree, parent)
	digests := tpm2.TPMLDigest{}
	for _, or := range ors {
		digests.Digests = append(digests.Digests, tpmutil.U16Bytes(or))
	}
	return tpm2.PolicyOr(tpm, s, digests)
}

// RunPolicy runs the satisfied TPM policy in the given session handle.
func RunPolicy(tpm io.ReadWriter, s tpmutil.Handle, p *policypb.Policy) error {
	norm, err := Normalize(p)
	if err != nil {
		return err
	}
	state, err := CurrentTpmState(tpm)
	if err != nil {
		return err
	}
	idx, err := FirstSatisfiable(norm, state)
	if err != nil {
		return err
	}
	tree, err := norm.CalculateTree(crypto.SHA256)
	if err != nil {
		return err
	}
	currentIndex, err := tree.leafIndex(*idx)
	if err != nil {
		return err
	}
	for i, rule := range norm[*idx] {
		if err = RunRule(tpm, s, rule); err != nil {
			return fmt.Errorf("on normalized branch %d, rule %d: %w", *idx, i, err)
		}
	}
	for *currentIndex != 0 {
		parent := eighttree.ParentIndex(*currentIndex)
		if err = RunOr(tpm, s, tree, *currentIndex); err != nil {
			return fmt.Errorf("or-ing up from node %d to node %d: %w", *currentIndex, parent, err)
		}
		*currentIndex = parent
	}
	return nil
}

// isSatisfiable returns whether a rule would pass if enforced by the TPM whose
// current state is described by currentState.
func isSatisfiable(rule *policypb.Rule, currentState *TpmState) bool {
	switch x := rule.Assertion.(type) {
	case *policypb.Rule_Spam:
		return isSpamSatisfiable(x.Spam, currentState)
	default:
		return false
	}
}

// isSpamSatisfiable returns whether a spam rule would pass if enforced by the
// TPM whose current state is described by currentState.
func isSpamSatisfiable(rule *policypb.SpamRule, currentState *TpmState) bool {
	if rule.Offset+uint32(len(rule.Operand)) > 64 {
		// not a valid policy
		return false
	}
	contents, ok := currentState.Spams[rule.Index]
	if !ok {
		// The indicated spam is not written so it cannot be compared.
		// N.B.: If the indicated spam is defined but not written,
		// anybody could write anything to it and satisfy the policy.
		return false
	}
	spamOperand := contents[rule.Offset:len(rule.Operand)]
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

// signedBig transforms a signed 2's complement big integer for unsigned
// Cmp operations by adding 2^(bitlength(a)) if the number is positive.
func signedBig(a []byte) *big.Int {
	result := big.NewInt(0)
	if len(a) > 0 {
		// Check sign bit and prepend 0x01 if positive
		if (a[0] >> 7) == 0 {
			a = append([]byte{0x01}, a...)
		}
		result.SetBytes(a)
	}
	return result
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
