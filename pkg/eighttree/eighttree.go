// package eighttree provides helpers for manipulating complete 8-trees.
package eighttree

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidTree = errors.New("invalid tree")
)

// InternalCountFromLeaves returns the number of internal nodes needed to store the given number of
// leaf nodes in a complete 8-tree representation.
func InternalCountFromLeaves(leafNodes int) int {
	if leafNodes < 2 {
		// One leaf needs no parent; don't worry about nonsense inputs <1
		return 0
	}
	// When a leaf node is promoted, it has two leaves. There is a promotion every 7 leaves added.
	// 2-8 leaves require 1 internal nodes (A with 1-8 leaves).
	// 9-15 leaves require 2 internal nodes (A with B and 7 leaves; B with 2-8 leaves).
	// 16-22 leaves require 3 internal nodes (A with B, C, and 6 leaves; B: 8 leaves; C: 2-8 leaves).
	// 64 leaves require 9 internal nodes (A with B-I which each have 8 leaves).
	// 65 leaves require 10 internal nodes:
	// (A with B-I which have 8 leaves, except B which has J (which has 8 leaves) and 1 leaf).
	return ((leafNodes - 2) / 7) + 1
}

// internalCountFromTotal returns the number of internal nodes in a tree with the given number of
// total nodes.
func InternalCountFromTotal(totalNodes int) (int, error) {
	if totalNodes == 1 {
		// One leaf needs no parent.
		return 0, nil
	}
	// There are a number of invalid total amounts of leaves: 2, 10, 18, ..., 8n + 2.
	// This is because promoting a leaf to an internal node gives it two children.
	if (totalNodes < 1) || ((totalNodes-2)%8 == 0) {
		return 0, fmt.Errorf("%w: %d nodes", ErrInvalidTree, totalNodes)
	}
	// 3-9 total nodes have 1 internal node (A with 1-8 leaves).
	// 11-17 total have 2 internal (A with B and 7 leaves; B with 2-8 leaves).
	// 19-25 total have 3 internal (A with B, C, and 6 leaves; B: 8 leaves; C: 2-8 leaves).
	// 73 total have 9 internal nodes (A with B-I which each have 8 leaves.
	// 75 total have 10.
	return ((totalNodes - 3) / 8) + 1, nil

}

// ParentIndex returns the index into the complete array representation of the given node's parent.
func ParentIndex(child int) int {
	return (child - 1) / 8
}

// ChildIndex returns the index into the complete array representation of the nth child node.
func ChildIndex(parent, n int) int {
	return (8 * parent) + n + 1
}
