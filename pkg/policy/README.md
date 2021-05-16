# policy

package policy provides helpers for running the TPM2 policy rules
corresponding to spam policy checks.

## Functions

### func [Extend](/policy.go#L33)

`func Extend(alg crypto.Hash, currentPolicy []byte, rule *policypb.Rule) ([]byte, error)`

Extend calculates the policy hash for a rule, given a starting policy, with the specified algorithm.

### func [For](/policy.go#L20)

`func For(alg crypto.Hash, rules []*policypb.Rule) ([]byte, error)`

For calculates the TPM policy hash for the given sequence of rules, with the specified algorithm.

### func [FromTextpbOrPanic](/policy.go#L121)

`func FromTextpbOrPanic(textpb string) *policypb.Policy`

FromTextpbOrPanic returns a Policy parsed from a given textpb.

### func [RuleFromTextpbOrPanic](/policy.go#L130)

`func RuleFromTextpbOrPanic(textpb string) *policypb.Rule`

RuleFromTextpbOrPanic returns a Rule parsed from a given textpb.

### func [RunRule](/policy.go#L43)

`func RunRule(tpm io.ReadWriter, s tpmutil.Handle, r *policypb.Rule) error`

RunRule runs the rule in the given session handle.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
