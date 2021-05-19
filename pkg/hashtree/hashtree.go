// package hashtree provides helpers for building and walking TPM2 PolicyOR trees.
package hashtree

import (
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"

	"github.com/chrisfenner/tpm-spam/pkg/behash"
	"github.com/chrisfenner/tpm-spam/pkg/eighttree"
)

var (
	ErrNodeIndexOutOfBounds = errors.New("node index out of bounds")
	ErrEmptyTree            = errors.New("tree is empty")
	ErrNodeNotAChild        = errors.New("node not a child")
)

// PolicyHashTree represents a TPM2_PolicyOR tree as a complete 8-tree, where all internal nodes are hashes of PolicyOR
// commands, and all leaf nodes represent concrete policies used to create the tree.
// normalized sublist's policy.
type PolicyHashTree [][]byte

// Root returns the root of the tree.
func (t PolicyHashTree) Root() ([]byte, error) {
	if len(t) == 0 {
		return nil, fmt.Errorf("%w", ErrEmptyTree)
	}
	return t[0], nil
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
		return fmt.Errorf("%d: %w", index, ErrNodeNotAChild)
	}
	if index >= len(tree) {
		return fmt.Errorf("%d: %w", index, ErrNodeIndexOutOfBounds)
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
		return nil, fmt.Errorf("leaf %d: %w", i, ErrNodeIndexOutOfBounds)
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
	args := make([]interface{}, 0, 2+len(children))
	args = append(args, result)
	args = append(args, uint32(0x171))
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
