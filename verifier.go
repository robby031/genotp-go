package genotp

import (
	"sync"
)

const defaultMaxUsedCodes = 10000

func replayKey(code string, context []byte) []byte {
	k := make([]byte, 0, len(code)+1+len(context))
	k = append(k, []byte(code)...)
	k = append(k, 0)
	k = append(k, context...)
	return k
}

type Verifier struct {
	usedCodes    map[string]struct{}
	maxUsedCodes int
	maxAttempts  uint32
	attempts     uint32
	mu           sync.RWMutex
}

func NewVerifier(maxAttempts uint32) *Verifier {
	return &Verifier{
		usedCodes:    make(map[string]struct{}),
		maxUsedCodes: defaultMaxUsedCodes,
		maxAttempts:  maxAttempts,
	}
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

	key := string(replayKey(code, issuedContext))
	if _, exists := v.usedCodes[key]; exists {
		return false
	}

	ctxMatch := constTimeEqBytes(issuedContext, requestContext)
	codeMatch := constantTimeEq(code, expected)

	if !ctxMatch || !codeMatch {
		v.attempts++
		return false
	}

	if len(v.usedCodes) >= v.maxUsedCodes {
		v.usedCodes = make(map[string]struct{})
	}

	v.usedCodes[key] = struct{}{}
	v.attempts = 0
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
