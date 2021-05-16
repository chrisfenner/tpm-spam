// package spamdef provides some common definitions for TPM spams that don't
// need to be exposed in the main spam API, but should be unit testable.
package spamdef

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"

	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"

	"github.com/chrisfenner/tpm-spam/pkg/behash"
)

// TPMSpamOffset is the offset of the first spam in TPM NV memory.
// This is in "reserved Platform Handles" space per
// [TCG](https://www.trustedcomputinggroup.org/wp-content/uploads/131011-Registry-of-reserved-TPM2-handles-and-localities.pdf).
const TPMSpamOffset = 0x017F0000

// TPMSpamAttributes is the set of TPM NV attributes for spam. As these are essential
// to the security properties of the library, they are discussed here.
// Attribute rationales:
// * [ ] `TPMA_NV_PPWRITE` = 0: Can't write with Platform Authorization
// * [ ] `TPMA_NV_OWNERWRITE` = 0: Can't write with Owner Authorization
// * [ ] `TPMA_NV_AUTHWRITE` = 0: Can't write with Auth Value
// * [x] `TPMA_NV_POLICYWRITE` = 1: Can write with Policy
// * [ ] `TPMA_NV_POLICY_DELETE` = 0: Can delete with Platform Authorization
// * [ ] `TPMA_NV_WRITELOCKED` = 0: Not write locked (can't be set at creation)
// * [x] `TPMA_NV_WRITEALL` = 1: A partial write of the data is not allowed
// * [ ] `TPMA_NV_WRITEDEFINE` = 0: May not be permanently write-locked
// * [ ] `TPMA_NV_WRITE_STCLEAR` = 0: May not be write-locked until next boot
// * [ ] `TPMA_NV_GLOBALLOCK` = 0: Is not affected by the global NV lock
// * [ ] `TPMA_NV_PPREAD` = 0: Can't read with Platform Authorization
// * [ ] `TPMA_NV_OWNERREAD` = 0: Can't read with Owner Authorization
// * [x] `TPMA_NV_AUTHREAD` = 1: Can read with Auth Value
// * [ ] `TPMA_NV_POLICYREAD` = 0: Can't read with Policy
// * [x] `TPMA_NV_NO_DA` = 1: Exempt from Dictionary Attack logic
// * [x] `TPMA_NV_ORDERLY` = 1: Only required t obe saved when shut down
// * [x] `TPMA_NV_CLEAR_STCLEAR` = 1: TPMA_NV_WRITTEN is cleared by reboot
// * [ ] `TPMA_NV_READLOCKED` = 0: Not read locked (can't be set at creation)
// * [ ] `TPMA_NV_WRITTEN` = 0: Not already written (can't be set at creation)
// * [x] `TPMA_NV_PLATFORMCREATE` = 1: Undefined with Platform, not Owner Auth
// * [ ] `TPMA_NV_READ_STCLEAR` = 0: May not be read-locked
const TPMSpamAttributes tpm2.NVAttr = tpm2.AttrPolicyWrite |
	tpm2.AttrWriteAll |
	tpm2.AttrAuthRead |
	tpm2.AttrNoDA |
	tpm2.AttrOrderly |
	tpm2.AttrClearSTClear |
	tpm2.AttrPlatformCreate

// Handle returns the TPM NV index associated with the given spam handle.
func Handle(index uint16) (*tpmutil.Handle, error) {
	if index > 0xffff {
		return nil, fmt.Errorf("invalid spam index %d (must be a uint16)", index)
	}
	result := tpmutil.Handle(TPMSpamOffset + uint32(index))
	return &result, nil
}

// Template returns the TPM NV template for a spam index.
func Template(index uint16) (*tpm2.NVPublic, error) {
	handle, err := Handle(index)
	if err != nil {
		return nil, err
	}
	policy, err := Policy(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("could not calculate spam policy: %w", err)
	}
	return &tpm2.NVPublic{
		NVIndex:    *handle,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: TPMSpamAttributes,
		AuthPolicy: tpmutil.U16Bytes(policy),
		DataSize:   64,
	}, nil
}

// Policy returns the Policy hash for defining a TPM NV index as spam.
func Policy(alg crypto.Hash) ([]byte, error) {
	result := make([]byte, alg.Size())
	// PolicyNV(false)
	return behash.HashItems(alg, result, uint32(0x18f), uint8(0))
}

// Name returns the TPM name for a spam index.
func Name(index uint16) ([]byte, error) {
	alg := crypto.SHA256
	template, err := Template(index)
	if err != nil {
		return nil, err
	}
	template.Attributes |= tpm2.AttrWritten
	packed, err := tpmutil.Pack(template)
	if err != nil {
		return nil, err
	}
	hash, err := behash.HashItems(alg, packed)
	if err != nil {
		return nil, err
	}
	tpmAlg, err := tpm2.HashToAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err = binary.Write(&buf, binary.BigEndian, tpmAlg); err != nil {
		return nil, err
	}
	if _, err = buf.Write(hash); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
