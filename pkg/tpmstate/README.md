# tpmstate

package tpmstate encapsulates a TPM state as relevant to spam policies.

## Types

### type [SpamContents](/pkg/tpmstate/tpmstate.go#L16)

`type SpamContents [64]byte`

SpamContents represents the contents of a spam.

### type [TpmState](/pkg/tpmstate/tpmstate.go#L19)

`type TpmState struct { ... }`

TpmState represents the spam policy-relevant current state in the TPM.

#### func [CurrentTpmState](/pkg/tpmstate/tpmstate.go#L24)

`func CurrentTpmState(tpm io.ReadWriter) (*TpmState, error)`

CurrentTpmState queries the TPM for its current spam-relevant state.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
