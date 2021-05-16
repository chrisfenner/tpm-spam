# policypb

## Types

### type [And](/pkg/policypb/policy.pb.go#L274)

`type And struct { ... }`

An And policy aggregates sub-policies, requiring all children to be satisfied.

### type [Comparison](/pkg/policypb/policy.pb.go#L35)

`type Comparison int32`

A Comparison operator describes how to match against a given value.
All integer comparisons are big-endian, unsigned.

### type [Or](/pkg/policypb/policy.pb.go#L323)

`type Or struct { ... }`

An Or policy aggregates sub-policies, requiring at least one child to be satisfied.

### type [Policy](/pkg/policypb/policy.pb.go#L100)

`type Policy struct { ... }`

A Policy represents an AND/OR policy tree describing a set of acceptable states.

### type [Policy_And](/pkg/policypb/policy.pb.go#L181)

`type Policy_And struct { ... }`

### type [Policy_Or](/pkg/policypb/policy.pb.go#L186)

`type Policy_Or struct { ... }`

### type [Policy_Rule](/pkg/policypb/policy.pb.go#L176)

`type Policy_Rule struct { ... }`

### type [Rule](/pkg/policypb/policy.pb.go#L372)

`type Rule struct { ... }`

A leaf rule that is some assertion against RoT state.

### type [Rule_Spam](/pkg/policypb/policy.pb.go#L432)

`type Rule_Spam struct { ... }`

### type [SpamRule](/pkg/policypb/policy.pb.go#L198)

`type SpamRule struct { ... }`

A Spam rule asserts a matcher against a sub-array of a spam.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
