package genotp

import (
	"sync"
)

const defaultMaxUsedCodes = 10000

func replayKey(dst []byte, code string, context []byte) []byte {
	dst = append(dst, code...)
	dst = append(dst, 0)
	dst = append(dst, context...)
	return dst
}

type replayBuf struct {
	bytes []byte
}

type Verifier struct {
	usedCodes    map[string]struct{}
	maxUsedCodes int
	maxAttempts  uint32
	attempts     uint32
	mu           sync.RWMutex
	bufPool      sync.Pool
}

func NewVerifier(maxAttempts uint32) *Verifier {
	v := &Verifier{
		usedCodes:    make(map[string]struct{}),
		maxUsedCodes: defaultMaxUsedCodes,
		maxAttempts:  maxAttempts,
	}
	v.bufPool.New = func() any {
		return &replayBuf{bytes: make([]byte, 0, 128)}
	}
	return v
}

func NewVerifierWithCapacity(maxAttempts uint32, maxUsedCodes int) *Verifier {
	return &Verifier{
		usedCodes:    make(map[string]struct{}),
		maxUsedCodes: maxUsedCodes,
		maxAttempts:  maxAttempts,
	}
}

func (v *Verifier) VerifyWithReplayProtection(code, expected string) bool {
	return v.verifyInner(code, expected, []byte{}, []byte{})
}

func (v *Verifier) VerifyWithContext(code, expected string, issuedContext, requestContext *OtpContext) bool {
	issuedBytes := []byte{}
	if issuedContext != nil {
		issuedBytes = issuedContext.Bytes()
	}

	requestBytes := []byte{}
	if requestContext != nil {
		requestBytes = requestContext.Bytes()
	}

	return v.verifyInner(code, expected, issuedBytes, requestBytes)
}

func (v *Verifier) verifyInner(code, expected string, issuedContext, requestContext []byte) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.attempts >= v.maxAttempts {
		return false
	}

	b := v.bufPool.Get().(*replayBuf)
	b.bytes = b.bytes[:0]

	b.bytes = replayKey(b.bytes, code, issuedContext)
	key := string(b.bytes)

	_, isReplay := v.usedCodes[key]

	ctxMatch := constTimeEqBytes(issuedContext, requestContext)
	codeMatch := constantTimeEq(code, expected)

	if isReplay || !ctxMatch || !codeMatch {
		v.attempts++
		v.bufPool.Put(b)
		return false
	}

	if len(v.usedCodes) >= v.maxUsedCodes {
		v.usedCodes = make(map[string]struct{})
	}

	v.usedCodes[key] = struct{}{}
	v.attempts = 0

	v.bufPool.Put(b)
	return true
}

func (v *Verifier) IsRateLimited() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.attempts >= v.maxAttempts
}

func (v *Verifier) ResetAttempts() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.attempts = 0
}

func (v *Verifier) ClearUsedCodes() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.usedCodes = make(map[string]struct{})
}
