# hashtree

package hashtree provides helpers for building and walking TPM2 PolicyOR trees.

## Types

### type [PolicyHashTree](/hashtree.go#L18)

`type PolicyHashTree [][]byte`

PolicyHashTree represents a TPM2_PolicyOR tree as a complete 8-tree, where all internal nodes are hashes of PolicyOR
commands, and and all leaf nodes represent concrete policies used to create the tree.
normalized sublist's policy.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
