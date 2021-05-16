# behash

package behash provides convenience functions for hashing big-endian stuff.

## Functions

### func [HashItems](/behash.go#L11)

`func HashItems(alg crypto.Hash, items ...interface{}) ([]byte, error)`

HashItems returns the hash of the concatenation of the given items with the given algorithm.
Uses big-endian byte ordering for integral items.

---
Readme created from Go doc with [goreadme](https://github.com/posener/goreadme)
