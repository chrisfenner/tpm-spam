// package behash provides convenience functions for hashing big-endian things.
package behash

import (
	"crypto"
	"encoding/binary"
)

// HashItems returns the hash of the concatenation of the given items with the given algorithm.
// Uses big-endian byte ordering for integral items.
func HashItems(alg crypto.Hash, items ...interface{}) ([]byte, error) {
	h := alg.New()
	for _, item := range items {
		if err := binary.Write(h, binary.BigEndian, item); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}
