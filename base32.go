package genotp

import (
	"encoding/base32"
	"errors"
	"sync"
)

var b32Inverse = [256]int8{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, // '2'-'7'
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, // 'A'-'O'
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 'P'-'Z'
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, // 'a'-'o'
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 'p'-'z'
}

var b32Pool = sync.Pool{
	New: func() any {
		b := make([]byte, 1024)
		return &b
	},
}

func EncodeBase32(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

func DecodeBase32(dst []byte, src string) (int, error) {
	bufPtr := b32Pool.Get().(*[]byte)
	buf := (*bufPtr)[:0]
	defer b32Pool.Put(bufPtr)

	for i := 0; i < len(src); i++ {
		c := src[i]
		if c == ' ' || c == '-' || c == '=' {
			continue
		}
		buf = append(buf, c)
	}

	if len(buf) == 0 {
		return 0, nil
	}

	var dstIdx int
	var buffer int64
	var bitsLeft uint

	for i := 0; i < len(buf); i++ {
		val := b32Inverse[buf[i]]
		if val < 0 {
			return 0, ErrInvalidSecret
		}

		buffer = (buffer << 5) | int64(val)
		bitsLeft += 5

		if bitsLeft >= 8 {
			bitsLeft -= 8
			if dstIdx >= len(dst) {
				return 0, errors.New("destination buffer too small")
			}
			dst[dstIdx] = byte(buffer >> bitsLeft)
			dstIdx++
		}
	}

	return dstIdx, nil
}
