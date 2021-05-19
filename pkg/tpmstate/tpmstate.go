// package tpmstate encapsulates a TPM state as relevant to spam policies.
package tpmstate

import (
	"fmt"
	"io"
	"math"

	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"

	"github.com/chrisfenner/tpm-spam/pkg/spamdef"
)

// SpamContents represents the contents of a spam.
type SpamContents [64]byte

// TpmState represents the spam policy-relevant current state in the TPM.
type TpmState struct {
	Spams map[uint16]SpamContents
}

// CurrentTpmState queries the TPM for its current spam-relevant state.
func CurrentTpmState(tpm io.ReadWriter) (*TpmState, error) {
	spams := make(map[uint16]SpamContents)
	for handle := uint32(spamdef.TPMSpamOffset); handle <= uint32(spamdef.TPMSpamOffset + math.MaxUint16); handle++ {
		handles, _, err := tpm2.GetCapability(tpm, tpm2.CapabilityHandles, 8, handle)
		if err != nil {
			return nil, err
		}
		for _, h := range handles {
			hdl, ok := h.(tpmutil.Handle)
			if !ok {
				return nil, fmt.Errorf("invalid data from GetCapability: %v", h)
			}
			if uint32(hdl) > handle {
				handle = uint32(hdl)
			}
			if uint32(hdl) > uint32(spamdef.TPMSpamOffset + math.MaxUint16) {
				continue
			}
			data, err := tpm2.NVReadEx(tpm, hdl, hdl, "", 64)
			if err != nil || len(data) != 64 {
				// There was a problem reading this index, maybe it's not a spam.
				continue
			}
			spamIndex := uint16(uint32(hdl) - spamdef.TPMSpamOffset)
			var spam SpamContents
			copy(spam[:], data)
			spams[spamIndex] = spam
		}
	}
	return &TpmState{
		Spams: spams,
	}, nil
}
