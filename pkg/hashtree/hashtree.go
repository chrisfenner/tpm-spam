package hashtree

import (
	"crypto"
	"fmt"
	"io"

	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"
	"github.com/chrisfenner/tpm-spam/pkg/behash"
	"github.com/chrisfenner/tpm-spam/pkg/eighttree"
)

// PolicyHashTree represents a TPM2_PolicyOR tree as a complete 8-tree, where all internal nodes are hashes of PolicyOR
// commands, and and all leaf nodes represent concrete policies used to create the tree.
// normalized sublist's policy.
type PolicyHashTree [][]byte

// Root returns the root of the tree.
func (t PolicyHashTree) Root() []byte {
	return t[0]
}

// At returns the hash at the given internal or leaf node.
func (t PolicyHashTree) At(node int) []byte {
	return t[node]
}

// Build creates a PolicyHashTree holding the given leaves.
func Build(alg crypto.Hash, leaves [][]byte) (*PolicyHashTree, error) {
	leafCount := len(leaves)
	internalCount := eighttree.InternalCountFromLeaves(leafCount)
	result := make(PolicyHashTree, internalCount+leafCount)

	for i := 0; i < leafCount; i++ {
		result[internalCount+i] = make([]byte, len(leaves[i]))
		copy(result[internalCount+i], leaves[i])
	}

	for i := internalCount - 1; i >= 0; i-- {
		if err := internalPolicy(&result[i], result, i, alg); err != nil {
			return nil, fmt.Errorf("failed to calculate internal policy %d: %w", i, err)
		}
	}

	return &result, nil
}

// ChildrenOf returns the digests of all the children of the given internal node. If the node is a leaf node, returns nil.
func (t PolicyHashTree) ChildrenOf(index int) [][]byte {
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

// RunOr runs the PolicyOr command to go from the given node to its parent, in the given TPM session handle.
func (tree PolicyHashTree) RunOr(tpm io.ReadWriter, s tpmutil.Handle, index int) error {
	if index <= 0 {
		return fmt.Errorf("specified node %d has no parent", index)
	}
	if index >= len(tree) {
		return fmt.Errorf("specified node %d does not exist", index)
	}
	parent := eighttree.ParentIndex(index)
	ors := tree.ChildrenOf(parent)
	digests := tpm2.TPMLDigest{}
	for _, or := range ors {
		digests.Digests = append(digests.Digests, tpmutil.U16Bytes(or))
	}
	return tpm2.PolicyOr(tpm, s, digests)
}

// LeafIndex returns the index of the given leaf in the tree.
func (t PolicyHashTree) LeafIndex(i int) (*int, error) {
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

// leaf returns a pointer to the given leaf in the tree.
func (t PolicyHashTree) leaf(i int) (*[]byte, error) {
	idx, err := t.LeafIndex(i)
	if err != nil {
		return nil, err
	}
	return &t[*idx], nil
}

// internalPolicy calculates the TPM policy hash for the given internal node, with the specified
// algorithm, storing it into policy.
// This function works on partially calculated policy trees, but it requires that all nodes after
// the given node have already been calculated.
func internalPolicy(policy *[]byte, t PolicyHashTree, index int, alg crypto.Hash) error {
	children := t.ChildrenOf(index)
	result := make([]byte, alg.Size())
	args := []interface{}{
		result, uint32(0x171),
	}
	// TODO: clean up this copy that gets around inability to cast [][]byte to []interface{}
	for _, child := range children {
		args = append(args, child)
	}
	result, err := behash.HashItems(alg, args...)
	if err != nil {
		return err
	}
	*policy = result
	return nil
}
