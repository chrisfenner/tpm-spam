package eighttree_test

import (
	"fmt"
	"github.com/chrisfenner/tpm-spam/pkg/eighttree"
	"testing"
)

func TestInternalCounts(t *testing.T) {
	cases := []struct {
		internal int
		leaves   int
		total    int
	}{
		{0, 1, 1},
		{1, 2, 3},
		{1, 8, 9},
		{2, 9, 11},
		{2, 15, 17},
		{3, 16, 19},
		{3, 22, 25},
		{9, 64, 73},
		{10, 65, 75},
	}

	for _, testCase := range cases {
		name := fmt.Sprintf("%d-%d-%d", testCase.internal, testCase.leaves, testCase.total)
		t.Run(name, func(t *testing.T) {
			t.Run("InternalCountFromLeaves", func(t *testing.T) {
				internal := eighttree.InternalCountFromLeaves(testCase.leaves)
				if internal != testCase.internal {
					t.Errorf("for %d leaves want %d, got %d",
						testCase.leaves, testCase.internal, internal)
				}
			})
			t.Run("InternalCountFromTotal", func(t *testing.T) {
				internal, err := eighttree.InternalCountFromTotal(testCase.total)
				if err != nil {
					t.Errorf("want nil got %v", err)
				}
				if internal != testCase.internal {
					t.Errorf("for %d total want %d, got %d",
						testCase.total, testCase.internal, internal)
				}
			})
		})
	}
}
