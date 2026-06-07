package genotp

import "math/bits"

func constantTimeEq(a, b string) bool {
	return constTimeEqBytes([]byte(a), []byte(b))
}

func constantTimeEqByteResult(a, b []byte) byte {
	lenA := len(a)
	lenB := len(b)
	maxLen := max(lenA, lenB)

	diff := uint(lenA ^ lenB)

	for i := 0; i < maxLen; i++ {
		var av, bv byte
		if i < lenA {
			av = a[i]
		}
		if i < lenB {
			bv = b[i]
		}
		diff |= uint(av ^ bv)
	}

	return byte(1 - ((diff | -diff) >> (bits.UintSize - 1)))
}

func constTimeEqBytes(a, b []byte) bool {
	lenA := len(a)
	lenB := len(b)
	maxLen := max(lenB, lenA)

	diff := uint(lenA ^ lenB)

	for i := 0; i < maxLen; i++ {
		var av, bv byte
		if i < lenA {
			av = a[i]
		}
		if i < lenB {
			bv = b[i]
		}
		diff |= uint(av ^ bv)
	}

	nonzero := (diff | -diff) >> (bits.UintSize - 1)
	return nonzero == 0
}
