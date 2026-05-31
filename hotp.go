package genotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"math"
	"sync"
)

const contextBindTag = "genotp-ctx-v1\x00"
const maxLookAhead = 10000

var contextBindTagBytes = []byte(contextBindTag)

const maxHMACSize = 64

type macBuf struct {
	mac     hash.Hash
	counter [8]byte
	sum     [maxHMACSize]byte
}

type HOTP struct {
	secret    []byte
	algorithm Algorithm
	digits    uint32
	modValue  uint32
	macPool   sync.Pool
	mu        sync.RWMutex
}

func NewHOTP(secret []byte, algorithm Algorithm, digits uint32) (*HOTP, error) {
	if digits < 6 || digits > 8 {
		return nil, ErrInvalidDigits
	}

	if len(secret) == 0 {
		return nil, ErrInvalidSecret
	}

	hashFn, ok := hashFuncFor(algorithm)
	if !ok {
		return nil, ErrInvalidAlgorithm
	}

	h := &HOTP{
		secret:    secret,
		algorithm: algorithm,
		digits:    digits,
		modValue:  uint32(math.Pow10(int(digits))),
	}

	h.macPool.New = func() any {
		return &macBuf{mac: hmac.New(hashFn, h.secret)}
	}
	return h, nil
}

func hashFuncFor(algorithm Algorithm) (func() hash.Hash, bool) {
	switch algorithm {
	case SHA1:
		return sha1.New, true
	case SHA256:
		return sha256.New, true
	case SHA512:
		return sha512.New, true
	default:
		return nil, false
	}
}

func (h *HOTP) Generate(counter uint64) (string, error) {
	var buf [8]byte
	out := h.genDigits(buf[:], counter, nil)
	return string(out), nil
}

func (h *HOTP) Verify(code string, counter uint64) (bool, error) {
	var userBuf [8]byte
	userBytes := userBuf[:copy(userBuf[:], code)]

	var expectedBuf [8]byte
	expected := h.genDigits(expectedBuf[:], counter, nil)
	return constTimeEqBytes(userBytes, expected), nil
}

func (h *HOTP) VerifyWithResync(code string, counter uint64, lookAhead uint64) (uint64, bool, error) {
	// Batasi lookAhead untuk mencegah brute-force
	effectiveLookAhead := min(lookAhead, maxLookAhead)

	var userBuf [8]byte
	userBytes := userBuf[:copy(userBuf[:], code)]

	for i := uint64(0); i <= effectiveLookAhead; i++ {
		testCounter := counter + i
		if testCounter < counter {
			break
		}

		var expectedBuf [8]byte
		expected := h.genDigits(expectedBuf[:], testCounter, nil)
		if constTimeEqBytes(userBytes, expected) {
			return testCounter, true, nil
		}
	}

	return 0, false, nil
}

func (h *HOTP) GenBound(counter uint64, context *OtpContext) (string, error) {
	var ctxBytes []byte
	if context != nil {
		ctxBytes = context.Bytes()
	}
	var buf [8]byte
	out := h.genDigits(buf[:], counter, ctxBytes)
	return string(out), nil
}

func (h *HOTP) VerifyBound(code string, counter uint64, context *OtpContext) (bool, error) {
	var ctxBytes []byte
	if context != nil {
		ctxBytes = context.Bytes()
	}
	var userBuf [8]byte
	userBytes := userBuf[:copy(userBuf[:], code)]

	var expectedBuf [8]byte
	expected := h.genDigits(expectedBuf[:], counter, ctxBytes)
	return constTimeEqBytes(userBytes, expected), nil
}

func (h *HOTP) genDigits(dst []byte, counter uint64, context []byte) []byte {
	code := h.computeTruncated(counter, context)
	return formatOTP(dst, code, h.digits)
}

func (h *HOTP) computeTruncated(counter uint64, context []byte) uint32 {
	mb := h.macPool.Get().(*macBuf)
	binary.BigEndian.PutUint64(mb.counter[:], counter)
	mb.mac.Reset()

	// Baca secret dengan mutex
	h.mu.RLock()
	mb.mac.Write(mb.counter[:])
	if len(context) > 0 {
		mb.mac.Write(contextBindTagBytes)
		mb.mac.Write(context)
	}
	hmacBytes := mb.mac.Sum(mb.sum[:0])
	h.mu.RUnlock()

	truncated := dynamicTruncate(hmacBytes, h.modValue)
	h.macPool.Put(mb)
	return truncated
}

func dynamicTruncate(hmacBytes []byte, modValue uint32) uint32 {
	offset := int(hmacBytes[len(hmacBytes)-1] & 0x0f)
	binary := ((uint32(hmacBytes[offset]) & 0x7f) << 24) |
		(uint32(hmacBytes[offset+1]) << 16) |
		(uint32(hmacBytes[offset+2]) << 8) |
		uint32(hmacBytes[offset+3])
	return binary % modValue
}

func formatOTP(dst []byte, code, digits uint32) []byte {
	d := int(digits)
	for i := d - 1; i >= 0; i-- {
		dst[i] = byte('0' + code%10)
		code /= 10
	}
	return dst[:d]
}

func (h *HOTP) ClearSecret() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i := range h.secret {
		h.secret[i] = 0
	}
}
