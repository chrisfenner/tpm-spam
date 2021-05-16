# policypb

## Types

### type [And](/policy.pb.go#L269)

`type And struct { ... }`

An And policy aggregates sub-policies, requiring all children to be satisfied.

### type [Comparison](/policy.pb.go#L30)

`type Comparison int32`

A Comparison operator describes how to match against a given value.
All integer comparisons are big-endian, unsigned.

### type [Or](/policy.pb.go#L318)

`type Or struct { ... }`

An Or policy aggregates sub-policies, requiring at least one child to be satisfied.

### type [Policy](/policy.pb.go#L95)

`type Policy struct { ... }`

A Policy represents an AND/OR policy tree describing a set of acceptable states.

### type [Policy_And](/policy.pb.go#L176)

`type Policy_And struct { ... }`

### type [Policy_Or](/policy.pb.go#L181)

`type Policy_Or struct { ... }`

### type [Policy_Rule](/policy.pb.go#L171)

`type Policy_Rule struct { ... }`

### type [Rule](/policy.pb.go#L367)

`type Rule struct { ... }`

A leaf rule that is some assertion against RoT state.

### type [Rule_Spam](/policy.pb.go#L427)

`type Rule_Spam struct { ... }`

### type [SpamRule](/policy.pb.go#L193)

`type SpamRule struct { ... }`

A Spam rule asserts a matcher against a sub-array of a spam.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
