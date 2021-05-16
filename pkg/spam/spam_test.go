package spam_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/chrisfenner/go-tpm/tpm2"
	_ "github.com/golang/protobuf/proto"
	"github.com/google/go-tpm-tools/simulator"
	"google.golang.org/protobuf/encoding/prototext"

	"github.com/chrisfenner/tpm-spam/pkg/policy"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/chrisfenner/tpm-spam/pkg/spam"
)

const (
	biosSpamIndex uint16 = iota
	bootloaderSpamIndex
	kernelSpamIndex
	initramfsSpamIndex
	applicationSpamIndex
)

type fakeSpamInfo struct {
	hash      [32]byte
	purpose   [8]byte
	major     uint64
	minor     uint64
	buildTime uint64
}

func purposeFromString(str string) [8]byte {
	var result [8]byte
	copy(result[:], []byte(str))
	return result
}

var (
	biosHash        = sha256.Sum256([]byte("bios verification key"))
	bootloaderHash  = sha256.Sum256([]byte("bootloader verification key"))
	kernelHash      = sha256.Sum256([]byte("kernel verification key"))
	initramfsHash   = sha256.Sum256([]byte("initramfs verification key"))
	applicationHash = sha256.Sum256([]byte("application verification key"))
)

func setupFakeSpams(t *testing.T, tpm io.ReadWriter) {
	t.Helper()
	// Let's write some semi-realistic spams.
	// For compactness, all the test spams will follow the same schema.
	// Spam schema can differ from index to index - the important thing is
	// that measurer and verifier agree on the schema.
	spams := []struct {
		index uint16
		info  fakeSpamInfo
	}{
		{
			index: biosSpamIndex,
			info: fakeSpamInfo{
				hash:      biosHash,
				purpose:   purposeFromString("DEBUG"),
				major:     10,
				minor:     3,
				buildTime: 1620708579,
			},
		},
		{
			index: bootloaderSpamIndex,
			info: fakeSpamInfo{
				hash:      bootloaderHash,
				purpose:   purposeFromString("PROD"),
				major:     2,
				minor:     77,
				buildTime: 1491230079,
			},
		},
		{
			index: kernelSpamIndex,
			info: fakeSpamInfo{
				hash:      kernelHash,
				purpose:   purposeFromString("DEV"),
				major:     999,
				minor:     123,
				buildTime: 159770000,
			},
		},
		{
			index: initramfsSpamIndex,
			info: fakeSpamInfo{
				hash:      initramfsHash,
				purpose:   purposeFromString("PROD"),
				major:     0,
				minor:     2,
				buildTime: 1600000000,
			},
		},
		{
			index: applicationSpamIndex,
			info: fakeSpamInfo{
				hash:      applicationHash,
				purpose:   purposeFromString("FIZZBUZZ"),
				major:     9,
				minor:     18,
				buildTime: 161091278,
			},
		},
	}

	for _, s := range spams {
		if err := spam.Define(tpm, s.index, ""); err != nil {
			t.Fatalf("could not define test spams: %v", err)
		}

		data := [64]byte{}
		var buf bytes.Buffer
		if err := binary.Write(&buf, binary.BigEndian, s.info); err != nil {
			t.Fatalf("could not format spam data: %v", err)
		}
		copy(data[:], buf.Bytes())
		if err := spam.Write(tpm, s.index, data); err != nil {
			t.Fatalf("could not write test spam: %v", err)
		}
	}
}

func escapeBytes(data []byte) string {
	var b strings.Builder
	for _, d := range data {
		fmt.Fprintf(&b, "\\x%x", d)
	}
	return b.String()
}

func fakeSpamPolicy(t *testing.T) *policypb.Policy {
	t.Helper()
	textpb := fmt.Sprintf(`
and {
  policy { and {
    policy { rule {
      spam { index: 0 offset: 0 comparison: EQ operand: "%s" }
    } }
    policy { or {
      policy { rule {
        spam { index: 0 offset: 32 comparison: EQ operand: "DEBUG" }
      } }
      policy { rule {
        spam { index: 0 offset: 32 comparison: EQ operand: "DEV" }
      } }
      policy { rule {
        spam { index: 0 offset: 32 comparison: EQ operand: "PROD" }
      } }
    } }
    policy { rule {
      spam { index: 0 offset: 40 comparison: GTE operand: "\x00\x00\x00\x00\x00\x00\x00\x09" }
    } }
  } }
}
	`, escapeBytes(biosHash[:]))
	// `, escapeBytes(biosHash), escapeBytes(bootloaderHash), escapeBytes(kernelHash), escapeBytes(initramfsHash), escapeBytes(applicationHash))
	var policy policypb.Policy
	if err := prototext.Unmarshal([]byte(textpb), &policy); err != nil {
		t.Fatalf("%v", err)
	}
	return &policy
}

func TestSpamSatisfyPolicy(t *testing.T) {
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator")
	}
	defer tpm.Close()

	setupFakeSpams(t, tpm)
	policy := fakeSpamPolicy(t)
	_, err = spam.GetPolicy(policy)
	if err != nil {
		t.Fatalf("could not calculate spam policy: %v", err)
	}

	handle, _, err := tpm2.StartAuthSession(
		tpm,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		t.Fatalf("could not start policy session: %v", err)
	}

	err = spam.SatisfyPolicy(tpm, handle, policy)
	if err != nil {
		t.Errorf("error from SatisfyPolicy: %v", err)
	}
}

func TestCalculatePolicy(t *testing.T) {
	cases := []struct {
		name    string
		hashHex string
		policy  *policypb.Policy
	}{
		{
			"single spam",
			"de5cd324ea036c8cd2af6e09f520400fb94b72c765f6251f96423d13a1050016",
			policy.FromTextpbOrPanic(`
rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } }
			`),
		},
		{
			"OR of 2 spams",
			"ee06b23e9cc1c6e9c42e29fdd99107963129aa91efebe244c726cec658eb802b",
			policy.FromTextpbOrPanic(`
or {
	policy { rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } } }
	policy { rule { spam { index: 2 offset: 4 comparison: NEQ operand: "bar" } } }
}
			`),
		},
		{
			"unnecessary AND",
			"de5cd324ea036c8cd2af6e09f520400fb94b72c765f6251f96423d13a1050016",
			policy.FromTextpbOrPanic(`
and { policy { rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } } } }
			`),
		},
		{
			"two unnecessary ANDs",
			"de5cd324ea036c8cd2af6e09f520400fb94b72c765f6251f96423d13a1050016",
			policy.FromTextpbOrPanic(`
and { policy { and { policy { rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } } } } } }
			`),
		},
		{
			"unnecessary OR",
			"de5cd324ea036c8cd2af6e09f520400fb94b72c765f6251f96423d13a1050016",
			policy.FromTextpbOrPanic(`
or { policy { rule { spam { index: 1 offset: 32 comparison: EQ operand: "foo" } } } }
			`),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			expectedPolicy, err := hex.DecodeString(testCase.hashHex)
			if err != nil {
				t.Fatalf("error decoding expected hex string: %v", err)
			}
			policy, err := spam.GetPolicy(testCase.policy)
			if err != nil {
				t.Errorf("error from CalculatePolicy: %v", err)
			} else {
				if !bytes.Equal(policy, expectedPolicy) {
					t.Errorf("want\n%v\ngot\n%v\n",
						hex.EncodeToString(expectedPolicy),
						hex.EncodeToString(policy))
				}
			}
		})
	}
}
