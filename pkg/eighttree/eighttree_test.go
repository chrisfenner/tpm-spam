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

func TestParentIndex(t *testing.T) {
	cases := []struct {
		parent   int
		children []int
	}{
		{0, []int{1, 2, 3, 4, 5, 6, 7, 8}},
		{1, []int{9, 10, 11, 12, 13, 14, 15, 16}},
		{2, []int{17, 18, 19, 20, 21, 22, 23, 24}},
	}

	for _, testCase := range cases {
		name := fmt.Sprintf("%d-%v", testCase.parent, testCase.children)
		t.Run(name, func(t *testing.T) {
			for i, testChild := range testCase.children {
				parent := eighttree.ParentIndex(testChild)
				if parent != testCase.parent {
					t.Errorf("want parent %d got %d", testCase.parent, parent)
				}
				child := eighttree.ChildIndex(testCase.parent, i)
				if child != testChild {
					t.Errorf("want child %d got %d", testChild, child)
				}
			}
		})
	}
}
