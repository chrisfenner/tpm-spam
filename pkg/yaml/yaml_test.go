package yaml_test

import (
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/encoding/prototext"

	"github.com/chrisfenner/tpm-spam/pkg/policy"
	"github.com/chrisfenner/tpm-spam/pkg/yaml"
)

func ExampleDecode() {
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

func TestDecode(t *testing.T) {
	cases := []struct {
		name      string
		yamlRepr  string
		protoRepr string
	}{
		{
			"And of two ors",
			`
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
    - spam:
        index: 2
        offset: 8
        gt: 0x00000005
    - spam:
        index: 2
        offset: 12
        gt: 0x0000000a
                        `,
			`
and {
  policy { or {
    policy { rule {
      spam { index: 1 offset: 0 comparison: EQ operand: "\x00\x01\x02\x03\x04\x05\x06\x07" }
    } }
    policy { rule {
      spam { index: 1 offset: 0 comparison: EQ operand: "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" }
    } }
  } }
  policy { or {
    policy { rule {
      spam { index: 2 offset: 8 comparison: GT operand: "\x00\x00\x00\x05" }
    } }
    policy { rule {
      spam { index: 2 offset: 12 comparison: GT operand: "\x00\x00\x00\x0A" }
    } }
  } }
}
			`,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			protoPolicy := policy.FromTextpbOrPanic(testCase.protoRepr)
			yamlPolicy, err := yaml.Decode(testCase.yamlRepr)
			if err != nil {
				t.Fatalf("want nil got %v", err)
			}
			if !proto.Equal(protoPolicy, yamlPolicy) {
				t.Errorf("want\n%+v\ngot\n%+v", protoPolicy, yamlPolicy)
			}
		})
	}
}

func TestEncode(t *testing.T) {
	cases := []struct {
		name      string
		protoRepr string
	}{
		{
			"And of two ors",
			`
and {
  policy { or {
    policy { rule {
      spam { index: 1 offset: 0 comparison: EQ operand: "\x00\x01\x02\x03\x04\x05\x06\x07" }
    } }
    policy { rule {
      spam { index: 1 offset: 0 comparison: EQ operand: "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" }
    } }
  } }
  policy { or {
    policy { rule {
      spam { index: 2 offset: 8 comparison: GT operand: "\x00\x00\x00\x05" }
    } }
    policy { rule {
      spam { index: 2 offset: 12 comparison: GT operand: "\x00\x00\x00\x0A" }
    } }
  } }
}
			`,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			protoPolicy := policy.FromTextpbOrPanic(testCase.protoRepr)
			yamlPolicy, err := yaml.Encode(protoPolicy)
			if err != nil {
				t.Fatalf("want nil got %v", err)
			}
			t.Logf("Generated YAML form:\n%s\n", *yamlPolicy)
			protoPolicy2, err := yaml.Decode(*yamlPolicy)
			if err != nil {
				t.Fatalf("want nil got %v", err)
			}
			if !proto.Equal(protoPolicy, protoPolicy2) {
				t.Errorf("want\n%+v\ngot\n%+v", protoPolicy, protoPolicy2)
			}
		})
	}
}
