# spam

package spam defines some library functions for dealing with spams.

## Functions

### func [Define](/spam.go#L21)

`func Define(tpm io.ReadWriter, slot uint16, platformAuth string) error`

Define sets up a spam at the specified slot.

### func [GetPolicy](/spam.go#L114)

`func GetPolicy(policy *policypb.Policy) ([]byte, error)`

GetPolicy gets the TPM policy hash for a given spam policy.

### func [Read](/spam.go#L71)

`func Read(tpm io.ReadWriter, slot uint16) (*[64]byte, error)`

Read reads the spam at the specified slot.

### func [SatisfyPolicy](/spam.go#L77)

`func SatisfyPolicy(tpm io.ReadWriter, session tpmutil.Handle, pol *policypb.Policy) error`

SatisfyPolicy runs a spam policy in the given policy session.
Fails if the policy is not satisfiable.

### func [Undefine](/spam.go#L127)

`func Undefine(tpm io.ReadWriter, slot uint16, platformAuth string) error`

Undefine undefines the spam at the specified slot.

### func [Write](/spam.go#L34)

`func Write(tpm io.ReadWriter, slot uint16, data [64]byte) error`

Write writes the spam at the specified slot.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
