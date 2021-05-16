# satisfaction

package satisfaction provides functionality for testing whether a spam
policy can be satisfied in a given state.

## Functions

### func [FirstSatisfiable](/satisfaction.go#L16)

`func FirstSatisfiable(policies normpolicy.NormalizedPolicy, currentState *tpmstate.TpmState) (*int, error)`

FirstSatisfiable finds the index of the first satisfiable policy branch, or returns an error if no policy was satisfiable.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
