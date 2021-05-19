# policy

package policy provides helpers for running the TPM2 policy rules
corresponding to spam policy checks.

## Variables

```golang
var (
    ErrInvalidType       = errors.New("invalid type")
    ErrInvalidIndex      = errors.New("invalid index")
    ErrInvalidComparison = errors.New("invalid comparison")
    ErrInvalidAssertion  = errors.New("invalid assertion")
    ErrNoSubpolicies     = errors.New("no subpolicies")
    ErrOverflow          = errors.New("offset + data length > 64")
    ErrNilPolicy         = errors.New("nil policy")
)
```

## Functions

### func [Extend](/pkg/policy/policy.go#L58)

`func Extend(alg crypto.Hash, currentPolicy []byte, rule *policypb.Rule) ([]byte, error)`

Extend calculates the policy hash for a rule, given a starting policy, with the specified algorithm.

### func [For](/pkg/policy/policy.go#L45)

`func For(alg crypto.Hash, rules []*policypb.Rule) ([]byte, error)`

For calculates the TPM policy hash for the given sequence of rules, with the specified algorithm.

### func [FromTextpbOrPanic](/pkg/policy/policy.go#L143)

`func FromTextpbOrPanic(textpb string) *policypb.Policy`

FromTextpbOrPanic returns a Policy parsed from a given textpb.

### func [RuleFromTextpbOrPanic](/pkg/policy/policy.go#L152)

`func RuleFromTextpbOrPanic(textpb string) *policypb.Rule`

RuleFromTextpbOrPanic returns a Rule parsed from a given textpb.

### func [RunRule](/pkg/policy/policy.go#L68)

`func RunRule(tpm io.ReadWriter, s tpmutil.Handle, r *policypb.Rule) error`

RunRule runs the rule in the given session handle.

## Types

### type [InvalidPolicyError](/pkg/policy/policy.go#L22)

`type InvalidPolicyError struct { ... }`

InvalidPolicyError indicates that something is wrong with a spam policy.

#### func (InvalidPolicyError) [Error](/pkg/policy/policy.go#L27)

`func (e InvalidPolicyError) Error() string`

#### func (InvalidPolicyError) [Unwrap](/pkg/policy/policy.go#L30)

`func (e InvalidPolicyError) Unwrap() error`

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
