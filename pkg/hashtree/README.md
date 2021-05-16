# hashtree

package hashtree provides helpers for building and walking TPM2 PolicyOR trees.

## Types

### type [PolicyHashTree](/pkg/hashtree/hashtree.go#L19)

`type PolicyHashTree [][]byte`

PolicyHashTree represents a TPM2_PolicyOR tree as a complete 8-tree, where all internal nodes are hashes of PolicyOR
commands, and and all leaf nodes represent concrete policies used to create the tree.
normalized sublist's policy.

#### func [Build](/pkg/hashtree/hashtree.go#L32)

`func Build(alg crypto.Hash, leaves [][]byte) (*PolicyHashTree, error)`

Build creates a PolicyHashTree holding the given leaves.

#### func (PolicyHashTree) [At](/pkg/hashtree/hashtree.go#L27)

`func (t PolicyHashTree) At(node int) []byte`

At returns the hash at the given internal or leaf node.

#### func (PolicyHashTree) [ChildrenOf](/pkg/hashtree/hashtree.go#L52)

`func (t PolicyHashTree) ChildrenOf(index int) [][]byte`

ChildrenOf returns the digests of all the children of the given internal node. If the node is a leaf node, returns nil.

#### func (PolicyHashTree) [LeafIndex](/pkg/hashtree/hashtree.go#L82)

`func (t PolicyHashTree) LeafIndex(i int) (*int, error)`

LeafIndex returns the index of the given leaf in the tree.

#### func (PolicyHashTree) [Root](/pkg/hashtree/hashtree.go#L22)

`func (t PolicyHashTree) Root() []byte`

Root returns the root of the tree.

#### func (PolicyHashTree) [RunOr](/pkg/hashtree/hashtree.go#L65)

`func (tree PolicyHashTree) RunOr(tpm io.ReadWriter, s tpmutil.Handle, index int) error`

RunOr runs the PolicyOr command to go from the given node to its parent, in the given TPM session handle.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
