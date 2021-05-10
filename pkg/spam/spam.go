// package spam defines some library functions for dealing with spams
package spam

import (
	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"
	"github.com/chrisfenner/tpm-spam/pkg/helpers"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"io"
)

// Define sets up a spam at the specified slot.
func Define(tpm io.ReadWriter, slot uint16, platformAuth string) error {
	template, err := helpers.SpamTemplate(slot)
	if err != nil {
		return err
	}
	auth := tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession,
		Auth:       []byte(platformAuth)}
	return tpm2.NVDefineSpaceEx(tpm, tpm2.HandlePlatform, "", *template, auth)
}

// Write writes the spam at the specified slot.
func Write(tpm io.ReadWriter, slot uint16, data [64]byte) error {
	handle, err := helpers.SpamHandle(slot)
	if err != nil {
		return err
	}

	sess, _, err := tpm2.StartAuthSession(
		tpm,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return err
	}
	defer tpm2.FlushContext(tpm, sess)

	if err := tpm2.PolicyNVWritten(tpm, sess, false); err != nil {
		return err
	}

	auth := tpm2.AuthCommand{
		Session:    sess,
		Attributes: tpm2.AttrContinueSession,
		Auth:       nil,
	}
	if err := tpm2.NVWriteEx(tpm, *handle, *handle, auth, data[:], 0); err != nil {
		return err
	}

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
	handle, err := helpers.SpamHandle(slot)
	if err != nil {
		return err
	}
	return tpm2.NVUndefineSpace(tpm, "", tpm2.HandlePlatform, *handle)
}
