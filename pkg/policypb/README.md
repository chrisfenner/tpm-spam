# policypb

## Variables

Enum value maps for Comparison.

```golang
var (
    Comparison_name = map[int32]string{
        0:  "EQ",
        1:  "NEQ",
        2:  "GT",
        3:  "GTE",
        4:  "LT",
        5:  "LTE",
        6:  "BITSET",
        7:  "BITCLEAR",
    }
    Comparison_value = map[string]int32{
        "EQ":       0,
        "NEQ":      1,
        "GT":       2,
        "GTE":      3,
        "LT":       4,
        "LTE":      5,
        "BITSET":   6,
        "BITCLEAR": 7,
    }
)
```

```golang
var File_policy_proto protoreflect.FileDescriptor
```

## Types

### type [And](/pkg/policypb/policy.pb.go#L274)

`type And struct { ... }`

An And policy aggregates sub-policies, requiring all children to be satisfied.

#### func (*And) [Descriptor](/pkg/policypb/policy.pb.go#L311)

`func (*And) Descriptor() ([]byte, []int)`

Deprecated: Use And.ProtoReflect.Descriptor instead.

#### func (*And) [GetPolicy](/pkg/policypb/policy.pb.go#L315)

`func (x *And) GetPolicy() []*Policy`

#### func (*And) [ProtoMessage](/pkg/policypb/policy.pb.go#L296)

`func (*And) ProtoMessage()`

#### func (*And) [ProtoReflect](/pkg/policypb/policy.pb.go#L298)

`func (x *And) ProtoReflect() protoreflect.Message`

#### func (*And) [Reset](/pkg/policypb/policy.pb.go#L283)

`func (x *And) Reset()`

#### func (*And) [String](/pkg/policypb/policy.pb.go#L292)

`func (x *And) String() string`

### type [Comparison](/pkg/policypb/policy.pb.go#L35)

`type Comparison int32`

A Comparison operator describes how to match against a given value.
All integer comparisons are big-endian, unsigned.

#### Constants

```golang
const (
    Comparison_EQ       Comparison = 0
    Comparison_NEQ      Comparison = 1
    Comparison_GT       Comparison = 2
    Comparison_GTE      Comparison = 3
    Comparison_LT       Comparison = 4
    Comparison_LTE      Comparison = 5
    Comparison_BITSET   Comparison = 6
    Comparison_BITCLEAR Comparison = 7
)
```

#### func (Comparison) [Descriptor](/pkg/policypb/policy.pb.go#L82)

`func (Comparison) Descriptor() protoreflect.EnumDescriptor`

#### func (Comparison) [Enum](/pkg/policypb/policy.pb.go#L72)

`func (x Comparison) Enum() *Comparison`

#### func (Comparison) [EnumDescriptor](/pkg/policypb/policy.pb.go#L95)

`func (Comparison) EnumDescriptor() ([]byte, []int)`

Deprecated: Use Comparison.Descriptor instead.

#### func (Comparison) [Number](/pkg/policypb/policy.pb.go#L90)

`func (x Comparison) Number() protoreflect.EnumNumber`

#### func (Comparison) [String](/pkg/policypb/policy.pb.go#L78)

`func (x Comparison) String() string`

#### func (Comparison) [Type](/pkg/policypb/policy.pb.go#L86)

`func (Comparison) Type() protoreflect.EnumType`

### type [Or](/pkg/policypb/policy.pb.go#L323)

`type Or struct { ... }`

An Or policy aggregates sub-policies, requiring at least one child to be satisfied.

#### func (*Or) [Descriptor](/pkg/policypb/policy.pb.go#L360)

`func (*Or) Descriptor() ([]byte, []int)`

Deprecated: Use Or.ProtoReflect.Descriptor instead.

#### func (*Or) [GetPolicy](/pkg/policypb/policy.pb.go#L364)

`func (x *Or) GetPolicy() []*Policy`

#### func (*Or) [ProtoMessage](/pkg/policypb/policy.pb.go#L345)

`func (*Or) ProtoMessage()`

#### func (*Or) [ProtoReflect](/pkg/policypb/policy.pb.go#L347)

`func (x *Or) ProtoReflect() protoreflect.Message`

#### func (*Or) [Reset](/pkg/policypb/policy.pb.go#L332)

`func (x *Or) Reset()`

#### func (*Or) [String](/pkg/policypb/policy.pb.go#L341)

`func (x *Or) String() string`

### type [Policy](/pkg/policypb/policy.pb.go#L100)

`type Policy struct { ... }`

A Policy represents an AND/OR policy tree describing a set of acceptable states.

#### func (*Policy) [Descriptor](/pkg/policypb/policy.pb.go#L140)

`func (*Policy) Descriptor() ([]byte, []int)`

Deprecated: Use Policy.ProtoReflect.Descriptor instead.

#### func (*Policy) [GetAnd](/pkg/policypb/policy.pb.go#L158)

`func (x *Policy) GetAnd() *And`

#### func (*Policy) [GetAssertion](/pkg/policypb/policy.pb.go#L144)

`func (m *Policy) GetAssertion() isPolicy_Assertion`

#### func (*Policy) [GetOr](/pkg/policypb/policy.pb.go#L165)

`func (x *Policy) GetOr() *Or`

#### func (*Policy) [GetRule](/pkg/policypb/policy.pb.go#L151)

`func (x *Policy) GetRule() *Rule`

#### func (*Policy) [ProtoMessage](/pkg/policypb/policy.pb.go#L125)

`func (*Policy) ProtoMessage()`

#### func (*Policy) [ProtoReflect](/pkg/policypb/policy.pb.go#L127)

`func (x *Policy) ProtoReflect() protoreflect.Message`

#### func (*Policy) [Reset](/pkg/policypb/policy.pb.go#L112)

`func (x *Policy) Reset()`

#### func (*Policy) [String](/pkg/policypb/policy.pb.go#L121)

`func (x *Policy) String() string`

### type [Policy_And](/pkg/policypb/policy.pb.go#L181)

`type Policy_And struct { ... }`

### type [Policy_Or](/pkg/policypb/policy.pb.go#L186)

`type Policy_Or struct { ... }`

### type [Policy_Rule](/pkg/policypb/policy.pb.go#L176)

`type Policy_Rule struct { ... }`

### type [Rule](/pkg/policypb/policy.pb.go#L372)

`type Rule struct { ... }`

A leaf rule that is some assertion against RoT state.

#### func (*Rule) [Descriptor](/pkg/policypb/policy.pb.go#L410)

`func (*Rule) Descriptor() ([]byte, []int)`

Deprecated: Use Rule.ProtoReflect.Descriptor instead.

#### func (*Rule) [GetAssertion](/pkg/policypb/policy.pb.go#L414)

`func (m *Rule) GetAssertion() isRule_Assertion`

#### func (*Rule) [GetSpam](/pkg/policypb/policy.pb.go#L421)

`func (x *Rule) GetSpam() *SpamRule`

#### func (*Rule) [ProtoMessage](/pkg/policypb/policy.pb.go#L395)

`func (*Rule) ProtoMessage()`

#### func (*Rule) [ProtoReflect](/pkg/policypb/policy.pb.go#L397)

`func (x *Rule) ProtoReflect() protoreflect.Message`

#### func (*Rule) [Reset](/pkg/policypb/policy.pb.go#L382)

`func (x *Rule) Reset()`

#### func (*Rule) [String](/pkg/policypb/policy.pb.go#L391)

`func (x *Rule) String() string`

### type [Rule_Spam](/pkg/policypb/policy.pb.go#L432)

`type Rule_Spam struct { ... }`

### type [SpamRule](/pkg/policypb/policy.pb.go#L198)

`type SpamRule struct { ... }`

A Spam rule asserts a matcher against a sub-array of a spam.

#### func (*SpamRule) [Descriptor](/pkg/policypb/policy.pb.go#L241)

`func (*SpamRule) Descriptor() ([]byte, []int)`

Deprecated: Use SpamRule.ProtoReflect.Descriptor instead.

#### func (*SpamRule) [GetComparison](/pkg/policypb/policy.pb.go#L259)

`func (x *SpamRule) GetComparison() Comparison`

#### func (*SpamRule) [GetIndex](/pkg/policypb/policy.pb.go#L245)

`func (x *SpamRule) GetIndex() uint32`

#### func (*SpamRule) [GetOffset](/pkg/policypb/policy.pb.go#L252)

`func (x *SpamRule) GetOffset() uint32`

#### func (*SpamRule) [GetOperand](/pkg/policypb/policy.pb.go#L266)

`func (x *SpamRule) GetOperand() []byte`

#### func (*SpamRule) [ProtoMessage](/pkg/policypb/policy.pb.go#L226)

`func (*SpamRule) ProtoMessage()`

#### func (*SpamRule) [ProtoReflect](/pkg/policypb/policy.pb.go#L228)

`func (x *SpamRule) ProtoReflect() protoreflect.Message`

#### func (*SpamRule) [Reset](/pkg/policypb/policy.pb.go#L213)

`func (x *SpamRule) Reset()`

#### func (*SpamRule) [String](/pkg/policypb/policy.pb.go#L222)

`func (x *SpamRule) String() string`

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
