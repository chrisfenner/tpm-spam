package policy

import (
	"crypto"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
)

// Calculate the TPM policy hash associated with the given spam policy, with the specified algorithm.
// If initialPolicy is nil, the hash starting from the new policy (all 0x00) is calculated.
func Calculate(policy *policypb.Rule, alg crypto.Hash, initialPolicy []byte) ([]byte, error) {
	return nil, nil
}
