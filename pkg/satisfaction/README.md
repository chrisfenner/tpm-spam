# satisfaction

package satisfaction provides functionality for testing whether a spam
policy can be satisfied in a given state.

## Variables

```golang
var (
    ErrUnsatisfiable = errors.New("policy could not be satisfied")
)
```

## Functions

### func [FirstSatisfiable](/pkg/satisfaction/satisfaction.go#L21)

`func FirstSatisfiable(policies normpolicy.NormalizedPolicy, currentState *tpmstate.TpmState) (*int, error)`

FirstSatisfiable finds the index of the first satisfiable policy branch, or returns an error if no policy was satisfiable.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
