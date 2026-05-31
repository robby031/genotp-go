package genotp

func constantTimeEq(a, b string) bool {
	return constantTimeEqBytes([]byte(a), []byte(b))
}

func constantTimeEqBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}
