# spamdef

package spamdef provides some common definitions for TPM spams that don't
need to be exposed in the main spam API, but should be unit testable.

## Constants

TPMSpamAttributes is the set of TPM NV attributes for spam. As these are essential
to the security properties of the library, they are discussed here.
Attribute rationales:
* [ ] `TPMA_NV_PPWRITE` = 0: Can't write with Platform Authorization
* [ ] `TPMA_NV_OWNERWRITE` = 0: Can't write with Owner Authorization
* [ ] `TPMA_NV_AUTHWRITE` = 0: Can't write with Auth Value
* [x] `TPMA_NV_POLICYWRITE` = 1: Can write with Policy
* [ ] `TPMA_NV_POLICY_DELETE` = 0: Can delete with Platform Authorization
* [ ] `TPMA_NV_WRITELOCKED` = 0: Not write locked (can't be set at creation)
* [x] `TPMA_NV_WRITEALL` = 1: A partial write of the data is not allowed
* [ ] `TPMA_NV_WRITEDEFINE` = 0: May not be permanently write-locked
* [ ] `TPMA_NV_WRITE_STCLEAR` = 0: May not be write-locked until next boot
* [ ] `TPMA_NV_GLOBALLOCK` = 0: Is not affected by the global NV lock
* [ ] `TPMA_NV_PPREAD` = 0: Can't read with Platform Authorization
* [ ] `TPMA_NV_OWNERREAD` = 0: Can't read with Owner Authorization
* [x] `TPMA_NV_AUTHREAD` = 1: Can read with Auth Value
* [ ] `TPMA_NV_POLICYREAD` = 0: Can't read with Policy
* [x] `TPMA_NV_NO_DA` = 1: Exempt from Dictionary Attack logic
* [ ] `TPMA_NV_ORDERLY` = 0: NV writes are not deferred til clean shutdown
* [x] `TPMA_NV_CLEAR_STCLEAR` = 1: TPMA_NV_WRITTEN is cleared by reboot
* [ ] `TPMA_NV_READLOCKED` = 0: Not read locked (can't be set at creation)
* [ ] `TPMA_NV_WRITTEN` = 0: Not already written (can't be set at creation)
* [x] `TPMA_NV_PLATFORMCREATE` = 1: Undefined with Platform, not Owner Auth
* [ ] `TPMA_NV_READ_STCLEAR` = 0: May not be read-locked

```golang
const TPMSpamAttributes tpm2.NVAttr = tpm2.AttrPolicyWrite |
    tpm2.AttrWriteAll |
    tpm2.AttrAuthRead |
    tpm2.AttrNoDA |
    tpm2.AttrClearSTClear |
    tpm2.AttrPlatformCreate
```

TPMSpamOffset is the offset of the first spam in TPM NV memory.
This is in "reserved Platform Handles" space per
[TCG](https://www.trustedcomputinggroup.org/wp-content/uploads/131011-Registry-of-reserved-TPM2-handles-and-localities.pdf).

```golang
const TPMSpamOffset = 0x017F0000
```

## Functions

### func [Handle](/pkg/spamdef/spamdef.go#L54)

`func Handle(index uint16) (*tpmutil.Handle, error)`

Handle returns the TPM NV index associated with the given spam handle.

### func [Name](/pkg/spamdef/spamdef.go#L89)

`func Name(index uint16) ([]byte, error)`

Name returns the TPM name for a spam index.

### func [Policy](/pkg/spamdef/spamdef.go#L82)

`func Policy(alg crypto.Hash) ([]byte, error)`

Policy returns the Policy hash for defining a TPM NV index as spam.

### func [Template](/pkg/spamdef/spamdef.go#L63)

`func Template(index uint16) (*tpm2.NVPublic, error)`

Template returns the TPM NV template for a spam index.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
