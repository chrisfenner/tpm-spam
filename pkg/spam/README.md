# spam

package spam defines some library functions for dealing with spams.

## Functions

### func [Define](/spam.go#L22)

`func Define(tpm io.ReadWriter, slot uint16, platformAuth string) error`

Define sets up a spam at the specified slot.

### func [GetPolicy](/spam.go#L115)

`func GetPolicy(policy *policypb.Policy) ([]byte, error)`

GetPolicy gets the TPM policy hash for a given spam policy.

### func [Read](/spam.go#L72)

`func Read(tpm io.ReadWriter, slot uint16) (*[64]byte, error)`

Read reads the spam at the specified slot.

### func [SatisfyPolicy](/spam.go#L78)

`func SatisfyPolicy(tpm io.ReadWriter, session tpmutil.Handle, pol *policypb.Policy) error`

SatisfyPolicy runs a spam policy in the given policy session.
Fails if the policy is not satisfiable.

### func [Undefine](/spam.go#L128)

`func Undefine(tpm io.ReadWriter, slot uint16, platformAuth string) error`

Undefine undefines the spam at the specified slot.

### func [Write](/spam.go#L35)

`func Write(tpm io.ReadWriter, slot uint16, data [64]byte) error`

Write writes the spam at the specified slot.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
