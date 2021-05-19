# normpolicy

package normpolicy provides normalization functions for spam policy proto trees.

## Types

### type [NormalizedPolicy](/pkg/normpolicy/normpolicy.go#L14)

`type NormalizedPolicy [][]*policypb.Rule`

NormalizedPolicy represents the normalized OR/AND list-of-lists form of a policy.

#### func [Normalize](/pkg/normpolicy/normpolicy.go#L34)

`func Normalize(p *policypb.Policy) (NormalizedPolicy, error)`

Normalize simplifies the policy tree (arbitrary AND/OR tree) into OR/AND list-of-lists form.
This function returns the equivalent policy as a list of list of Rules.
Each sublist of rules is a valid configuration, where all rules are ANDed together.
The outer list is an OR-aggregation of all valid configurations.
This is required because TPM2_PolicyOr checks that the current Policy hash is one of the
permitted policies, then replaces the current Policy hash with the hash of all permitted values.
A policy like PolicyFoo AND (PolicyBar OR PolicyBaz) could not be executed in the order:
(PolicyFoo, PolicyBar, PolicyOR), because the running Policy hash would never consist of just
PolicyBar (or PolicyBaz) - it would be based on PolicyFoo being executed before that.
This policy must be rearranged as one of the following:
1. (PolicyFoo AND PolicyBar) OR (PolicyFoo AND PolicyBaz)
2. (PolicyBar OR PolicyBaz) AND PolicyFoo.

This function rearranges to (1).

(2) requires an even more complex "normal form" of "OR/AND list-of-lists followed by extra
sequence of shared AND-rules" and does not reduce the number of ORed-together branches or the
length of the executed policy.

#### func (NormalizedPolicy) [CalculateTree](/pkg/normpolicy/normpolicy.go#L96)

`func (norm NormalizedPolicy) CalculateTree(alg crypto.Hash) (*hashtree.PolicyHashTree, error)`

CalculateTree calculates the PolicyHashTree corresponding to a given NormalizedPolicy, using the
given hash algorithm as the policy hash algorithm.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
