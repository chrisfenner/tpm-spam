# eighttree

package eighttree provides helpers for manipulating complete 8-trees.

## Variables

```golang
var (
    ErrInvalidTree = errors.New("invalid tree")
)
```

## Functions

### func [ChildIndex](/pkg/eighttree/eighttree.go#L57)

`func ChildIndex(parent, n int) int`

ChildIndex returns the index into the complete array representation of the nth child node.

### func [InternalCountFromLeaves](/pkg/eighttree/eighttree.go#L15)

`func InternalCountFromLeaves(leafNodes int) int`

InternalCountFromLeaves returns the number of internal nodes needed to store the given number of
leaf nodes in a complete 8-tree representation.

### func [InternalCountFromTotal](/pkg/eighttree/eighttree.go#L32)

`func InternalCountFromTotal(totalNodes int) (int, error)`

internalCountFromTotal returns the number of internal nodes in a tree with the given number of
total nodes.

### func [ParentIndex](/pkg/eighttree/eighttree.go#L52)

`func ParentIndex(child int) int`

ParentIndex returns the index into the complete array representation of the given node's parent.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
