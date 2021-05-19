# yaml

package yaml provides mechanisms for serializing and deserializing spam
policies in YAML.

spam uses protocol buffers as the canonical format for several reasons:
* Most invalid states are impossible to represent. For example, proto has sum
types, while Go does not.
* Efficient wire format for transmission and storage.
* The protocol buffer compiler writes all the risky parsing code.

That being said, for human consumption, textproto spam policies leave a bit
to be desired.

YAML is a JSON-based text serialization format that has human readability as
its top priority.

For very complex policies, the `define` key may be used to set up anchors
that can be referred to later, in the actual policy. See the below example.

## Variables

```golang
var (
    ErrBadSumType     = errors.New("too many members were set on this sum type")
    ErrInvalidOperand = errors.New("operand must be 0x followed by a hex string of at least 1 byte")
)
```

## Functions

### func [DebugString](/pkg/yaml/yaml.go#L374)

`func DebugString(p *policypb.Policy) string`

DebugString converts a spam policy into YAML or the error string from attempting to do so.

### func [Decode](/pkg/yaml/yaml.go#L339)

`func Decode(s string) (*policypb.Policy, error)`

Decode parses a YAML document for a spam policy, and converts it into the canonical protobuf form.

```golang
package main

import (
	"fmt"
	"github.com/chrisfenner/tpm-spam/pkg/yaml"
	"google.golang.org/protobuf/encoding/prototext"
)

func main() {
	policy := `
# Set up some anchors - these aren't part of the parsed policy until aliased.
define:
  - &spam2_major_version_greater_than_5
      spam:
        index: 2
        offset: 8
        gt: 0x00000005
  - &spam2_minor_version_greater_than_10
      spam:
        index: 2
        offset: 12
        gt: 0x0000000a
and:
  - or:
    - spam:
        index: 1
        offset: 0
        eq: 0x0001020304050607
    - spam:
        index: 1
        offset: 0
        eq: 0x08090A0B0C0D0E0F
  - or:
    - *spam2_major_version_greater_than_5
    - *spam2_minor_version_greater_than_10`
	proto := yaml.DecodeOrPanic(policy)
	opts := prototext.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}
	fmt.Println(opts.Format(proto))
}

```

### func [DecodeOrPanic](/pkg/yaml/yaml.go#L351)

`func DecodeOrPanic(s string) *policypb.Policy`

DecodeOrPanic parses a YAML document for a spam policy, or panics if there is an error.

### func [Encode](/pkg/yaml/yaml.go#L360)

`func Encode(p *policypb.Policy) (*string, error)`

Encode converts a spam policy from the canonical protobuf form into more human-readable YAML form.

## Types

### type [Policy](/pkg/yaml/yaml.go#L39)

`type Policy struct { ... }`

INTERNAL: Only exported for manipulation by the `yaml` package.

### type [SpamPolicy](/pkg/yaml/yaml.go#L48)

`type SpamPolicy struct { ... }`

INTERNAL: Only exported for manipulation by the `yaml` package.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
