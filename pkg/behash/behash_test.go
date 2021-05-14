package behash_test

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/chrisfenner/tpm-spam/pkg/behash"
)

func TestHashItems(t *testing.T) {
	cases := []struct {
		alg     crypto.Hash
		items   []interface{}
		hashHex string
	}{
		{
			alg:     crypto.SHA1,
			items:   []interface{}{},
			hashHex: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			alg:     crypto.SHA256,
			items:   []interface{}{},
			hashHex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			alg:     crypto.SHA384,
			items:   []interface{}{uint32(1)},
			hashHex: "14d0dce7a18d3ff1fb2d2d575d0d0137a9f6a5b12eb046887bd46e94e0f615adfce9f086700c27ed4feceb5da50cc162",
		},
		{
			alg:     crypto.SHA256,
			items:   []interface{}{[]byte{0xff, 0xff, 0xff}},
			hashHex: "5ae7e6a42304dc6e4176210b83c43024f99a0bce9a870c3b6d2c95fc8ebfb74c",
		},
		{
			alg:     crypto.SHA256,
			items:   []interface{}{byte(1), byte(2), byte(3), byte(4)},
			hashHex: "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
		},
		{
			alg:     crypto.SHA256,
			items:   []interface{}{[]byte{0xde, 0xad}, []byte{0xbe, 0xef}},
			hashHex: "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953",
		},
	}

	for i, testCase := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			expectedHash, err := hex.DecodeString(testCase.hashHex)
			if err != nil {
				t.Fatalf("error decoding hashHex: %v", err)
			}
			hash, err := behash.HashItems(testCase.alg, testCase.items...)
			if err != nil {
				t.Fatalf("error hashing items: %v", err)
			}
			if !bytes.Equal(hash, expectedHash) {
				t.Errorf("want %v\ngot %v\n", hex.EncodeToString(expectedHash), hex.EncodeToString(hash))
			}
		})
	}
}
