package hashtree_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/chrisfenner/go-tpm/tpm2"
	"github.com/chrisfenner/go-tpm/tpmutil"
	"github.com/google/go-tpm-tools/simulator"

	"github.com/chrisfenner/tpm-spam/pkg/eighttree"
	"github.com/chrisfenner/tpm-spam/pkg/normpolicy"
	"github.com/chrisfenner/tpm-spam/pkg/policy"
	"github.com/chrisfenner/tpm-spam/pkg/policypb"
	"github.com/chrisfenner/tpm-spam/pkg/spam"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func startTrialSession(tpm io.ReadWriter) (*tpmutil.Handle, error) {
	handle, _, err := tpm2.StartAuthSession(
		tpm,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionTrial,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return nil, err
	}
	return &handle, nil
}

func TestOrHashing(t *testing.T) {
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer tpm.Close()

	// Reference simulator is limited to 6 spams.
	// Since writing a spam changes its name, write randomly to them all.
	// Writing random data asserts that the actual contents (other than
	// nvWritten state) do not matter to the policy.
	for i := uint16(1); i <= 6; i++ {
		if err := spam.Define(tpm, i, ""); err != nil {
			t.Fatalf("could not define test spams: %v", err)
		}
		defer spam.Undefine(tpm, i, "")
		data := [64]byte{}
		if _, err := rand.Read(data[:]); err != nil {
			t.Fatalf("could not generate random data: %v", err)
		}
		if err := spam.Write(tpm, i, data); err != nil {
			t.Fatalf("could not write test spam: %v", err)
		}
	}

	// Instead of having a bunch of test cases here, share a large list of rules
	// among all the tests.
	leaves := [][]*policypb.Rule{
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: EQ operand: "frumious" }
			`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 2 offset: 2 comparison: NEQ operand: "bandersnatch" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 3 offset: 3 comparison: GT operand: "\x03" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 4 offset: 4 comparison: GTE operand: "\x03\x00" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 5 offset: 5 comparison: LT operand: "\xff\xff\xff" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 6 offset: 6 comparison: LTE operand: "\xff\xff\xff\xee" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: BITSET operand: "\x01\x01" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: BITCLEAR operand: "\xa0\xa0" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: EQ operand: "frumious" }
				`),
			policy.RuleFromTextpbOrPanic(`
spam { index: 2 offset: 2 comparison: NEQ operand: "bandersnatch" }
				`),
			policy.RuleFromTextpbOrPanic(`
spam { index: 3 offset: 3 comparison: GT operand: "\x03" }
				`),
			policy.RuleFromTextpbOrPanic(`
spam { index: 4 offset: 4 comparison: GTE operand: "\x03\x00" }
				`),
			policy.RuleFromTextpbOrPanic(`
spam { index: 5 offset: 5 comparison: LT operand: "\xff\xff\xff" }
				`),
			policy.RuleFromTextpbOrPanic(`
spam { index: 6 offset: 6 comparison: LTE operand: "\xff\xff\xff\xee" }
				`),
			policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: BITSET operand: "\x01\x01" }
				`),
			policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: BITCLEAR operand: "\xa0\xa0" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 3 offset: 0 comparison: EQ operand: "foo" }
				`),
			policy.RuleFromTextpbOrPanic(`
spam { index: 3 offset: 3 comparison: NEQ operand: "bar" }
				`),
			policy.RuleFromTextpbOrPanic(`
spam { index: 3 offset: 6 comparison: NEQ operand: "baz" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: LTE operand: "\xff" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 2 offset: 2 comparison: LTE operand: "\xff" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 4 offset: 3 comparison: LTE operand: "\xff" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 5 offset: 5 comparison: LTE operand: "\xff" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 6 offset: 6 comparison: LTE operand: "\xff" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 1 offset: 1 comparison: LTE operand: "\xff" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 2 offset: 2 comparison: LTE operand: "\xff" }
				`),
		},
		{
			policy.RuleFromTextpbOrPanic(`
spam { index: 3 offset: 3 comparison: LTE operand: "\xff" }
				`),
		},
	}

	// Assemble a policy tree of each possible size (up to all the rules above),
	// then walk from each leaf all the way to the root and check that we agree
	// with the TPM's hash.
	for size := 2; size < len(leaves); size++ {
		policy := normpolicy.NormalizedPolicy(leaves[:size])
		tree, err := policy.CalculateTree(crypto.SHA256)
		if err != nil {
			t.Fatalf("error from CalculateTree: %v", err)
		}
		for startLeaf := 0; startLeaf < len(policy); startLeaf++ {
			t.Run(fmt.Sprintf("start-at-%d-of-%d", startLeaf, size), func(t *testing.T) {
				sess, err := startTrialSession(tpm)
				if err != nil {
					t.Fatalf("could not start trial session: %v", err)
				}
				defer tpm2.FlushContext(tpm, *sess)

				// Walk the tree from each leaf to the root and verify hashes.
				node, err := tree.LeafIndex(startLeaf)
				if err != nil {
					t.Fatalf("could not find leaf index %d: %v", startLeaf, err)
				}

				for *node != 0 {
					if err := tree.RunOr(tpm, *sess, *node); err != nil {
						t.Fatalf("RunOr: %v", err)
					}
					*node = eighttree.ParentIndex(*node)
					digest, err := tpm2.PolicyGetDigest(tpm, *sess)
					if err != nil {
						t.Fatalf("PolicyGetDigest: %v", err)
					}
					if !bytes.Equal(digest, tree.At(*node)) {
						t.Errorf("for node %d want:\n%s\ngot:\n%s\n",
							*node,
							hex.EncodeToString(digest),
							hex.EncodeToString(tree.At(*node)))
					}
				}
			})
		}
	}
}
