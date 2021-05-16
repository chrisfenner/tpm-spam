// package spam defines some library functions for dealing with spams.
package spam

import (
	"crypto"
	"fmt"
	"io"

	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"

	"github.com/chrisfenner/tpm-spam/pkg/eighttree"
	"github.com/chrisfenner/tpm-spam/pkg/normpolicy"
	"github.com/chrisfenner/tpm-spam/pkg/policy"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/chrisfenner/tpm-spam/pkg/satisfaction"
	"github.com/chrisfenner/tpm-spam/pkg/spamdef"
	"github.com/chrisfenner/tpm-spam/pkg/tpmstate"
)

// Define sets up a spam at the specified slot.
func Define(tpm io.ReadWriter, slot uint16, platformAuth string) error {
	template, err := spamdef.Template(slot)
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
	handle, err := spamdef.Handle(slot)
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

// SatisfyPolicy runs a spam policy in the given policy session.
// Fails if the policy is not satisfiable.
func SatisfyPolicy(tpm io.ReadWriter, session tpmutil.Handle, pol *policypb.Policy) error {
	norm, err := normpolicy.Normalize(pol)
	if err != nil {
		return err
	}
	state, err := tpmstate.CurrentTpmState(tpm)
	if err != nil {
		return err
	}
	idx, err := satisfaction.FirstSatisfiable(norm, state)
	if err != nil {
		return err
	}
	tree, err := norm.CalculateTree(crypto.SHA256)
	if err != nil {
		return err
	}
	currentIndex, err := tree.LeafIndex(*idx)
	if err != nil {
		return err
	}
	for i, rule := range norm[*idx] {
		if err = policy.RunRule(tpm, session, rule); err != nil {
			return fmt.Errorf("on normalized branch %d, rule %d: %w", *idx, i, err)
		}
	}
	for *currentIndex != 0 {
		parent := eighttree.ParentIndex(*currentIndex)
		if err = tree.RunOr(tpm, session, *currentIndex); err != nil {
			return fmt.Errorf("or-ing up from node %d to node %d: %w", *currentIndex, parent, err)
		}
		*currentIndex = parent
	}
	return nil
}

// GetPolicy gets the TPM policy hash for a given spam policy.
func GetPolicy(policy *policypb.Policy) ([]byte, error) {
	norm, err := normpolicy.Normalize(policy)
	if err != nil {
		return nil, err
	}
	tree, err := norm.CalculateTree(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return tree.Root(), nil
}

// Undefine undefines the spam at the specified slot.
func Undefine(tpm io.ReadWriter, slot uint16, platformAuth string) error {
	handle, err := spamdef.Handle(slot)
	if err != nil {
		return err
	}
	return tpm2.NVUndefineSpace(tpm, "", tpm2.HandlePlatform, *handle)
}
