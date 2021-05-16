# spamdef

package spamdef provides some common definitions for TPM spams that don't
need to be exposed in the main spam API, but should be unit testable.

## Functions

### func [Handle](/spamdef.go#L17)

`func Handle(index uint16) (*tpmutil.Handle, error)`

Handle returns the TPM NV index associated with the given spam handle.

### func [Name](/spamdef.go#L81)

`func Name(index uint16) ([]byte, error)`

Name returns the TPM name for a spam index.

### func [Policy](/spamdef.go#L74)

`func Policy(alg crypto.Hash) ([]byte, error)`

Policy returns the Policy hash for defining a TPM NV index as spam.

### func [Template](/spamdef.go#L26)

`func Template(index uint16) (*tpm2.NVPublic, error)`

Template returns the TPM NV template for a spam index.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
