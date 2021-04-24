// package spam defines some library functions for dealing with spams
package spam

import (
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	_ "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"io"
)

// Define sets up a spam at the specified slot.
func Define(tpm io.ReadWriter, slot uint16, platformAuth string) error {
	// TODO: NVDefineSpace to set up an NV index
	// Index: 0x017F0000 (Platform Reserved) + slot
	//   Rationale: Some slot in the Platform range.
	//              Due to limitations of TPM, spams need to be defined with
	//              Platform authorization by the code measured into PCR[00].
	//              This code is expected to randomize Platform auth and
	//              discard it, losing Platform auth until next boot.
	//              This prevents undefine-and-redefine by later code that
	//              not measured into PCR[00].
	//              Because spam requires cooperation from the code that
	//              controls Platform auth, use an index in Platform range.
	// NameAlg: SHA2-256
	// AuthPolicy: PolicyNvWritten(NO)
	//   Rationale: Can only write once per boot. This prevents measured
	//              software from overwriting its own measurements.
	// Auth: Empty Auth
	//   Rationale: Auth only allows reading the index (see below).
	// Size: 64 bytes:
	//   Rationale: 256-bit hash times 2 (Verification key + Signed token)
	// Type: Ordinary index
	// Attributes:
	//   TPMA_NV_PPWRITE = 0: Can't write with Platform Authorization
	//   TPMA_NV_OWNERWRITE = 0: Can't write with Owner Authorization
	//   TPMA_NV_AUTHWRITE = 0: Can't write with Auth Value
	//   TPMA_NV_POLICYWRITE = 1: Can write with Policy
	//   TPMA_NV_POLICY_DELETE = 0: Can delete with Platform Authorization
	//   TPMA_NV_WRITELOCKED = 0: Not write locked (can't be set at creation)
	//   TPMA_NV_WRITEALL = 1: A partial write of the data is not allowed
	//   TPMA_NV_WRITEDEFINE = 0: May not be permanently write-locked
	//   TPMA_NV_WRITE_STCLEAR = 0: May not be write-locked until next boot
	//   TPMA_NV_GLOBALLOCK = 0: Is not affected by the global NV lock
	//   TPMA_NV_PPREAD = 0: Can't read with Platform Authorization
	//   TPMA_NV_OWNERREAD = 0: Can't read with Owner Authorization
	//   TPMA_NV_AUTHREAD = 1: Can read with Auth Value
	//   TPMA_NV_POLICYREAD = 0: Can't read with Policy
	//   TPMA_NV_NO_DA = 1: Exempt from Dictionary Attack logic
	//   TPMA_NV_ORDERLY = 1: Only required t obe saved when shut down
	//   TPMA_NV_CLEAR_STCLEAR = 1: TPMA_NV_WRITTEN is cleared by reboot
	//   TPMA_NV_READLOCKED = 0: Not read locked (can't be set at creation)
	//   TPMA_NV_WRITTEN = 0: Not already written (can't be set at creation)
	//   TPMA_NV_PLATFORMCREATE = 1: Undefined with Platform, not Owner Auth
	//   TPMA_NV_READ_STCLEAR = 0: May not be read-locked
	return nil
}

// Write writes the spam at the specified slot.
func Write(tpm io.ReadWriter, slot uint16, data [64]byte) error {
	// TODO: NVWrite using the auth policy.
	return nil
}

// Read reads the spam at the specified slot.
func Read(tpm io.ReadWriter, slot uint16) (*[64]byte, error) {
	return nil, nil
}

// Policy adds a policy check against a particular spam.
func Policy(tpm io.ReadWriter, session tpmutil.Handle, policy *policypb.Rule) error {
	// TODO: Feed the check into PolicyNV
	return nil
}

// Undefine undefines the spam at the specified slot.
func Undefine(tpm io.ReadWriter, slot uint16, platformAuth string) error {
	// TODO: NVUndefineSpace of the index using platform auth.
	return nil
}
