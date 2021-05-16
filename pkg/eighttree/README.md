# eighttree

package eighttree provides helpers for manipulating complete 8-trees.

## Functions

### func [ChildIndex](/eighttree.go#L52)

`func ChildIndex(parent, n int) int`

ChildIndex returns the index into the complete array representation of the nth child node.

### func [InternalCountFromLeaves](/eighttree.go#L10)

`func InternalCountFromLeaves(leafNodes int) int`

InternalCountFromLeaves returns the number of internal nodes needed to store the given number of
leaf nodes in a complete 8-tree representation.

### func [InternalCountFromTotal](/eighttree.go#L27)

`func InternalCountFromTotal(totalNodes int) (int, error)`

internalCountFromTotal returns the number of internal nodes in a tree with the given number of
total nodes.

### func [ParentIndex](/eighttree.go#L47)

`func ParentIndex(child int) int`

ParentIndex returns the index into the complete array representation of the given node's parent.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
