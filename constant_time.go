package genotp

func constantTimeEq(a, b string) bool {
	return constTimeEqBytes([]byte(a), []byte(b))
}

func constantTimeEqByteResult(a, b []byte) byte {
	lenA := len(a)
	lenB := len(b)
	maxLen := max(lenA, lenB)

	diff := uint32(lenA) ^ uint32(lenB)

	for i := 0; i < maxLen; i++ {
		var av, bv byte
		if i < lenA {
			av = a[i]
		}
		if i < lenB {
			bv = b[i]
		}
		diff |= uint32(av ^ bv)
	}

	return byte(1 - ((diff | -diff) >> 31))
}

func constTimeEqBytes(a, b []byte) bool {
	lenA := len(a)
	lenB := len(b)
	maxLen := max(lenB, lenA)

	diff := uint32(lenA) ^ uint32(lenB)

	for i := 0; i < maxLen; i++ {
		var av, bv byte
		if i < lenA {
			av = a[i]
		}
		if i < lenB {
			bv = b[i]
		}
		diff |= uint32(av ^ bv)
	}

	nonzero := (diff | -diff) >> 31
	return nonzero == 0
}
