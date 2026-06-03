package genotp

import (
	"sync"
	"time"
)

const defaultMaxUsedCodes = 10000

const defaultReplayTTL = 90 * time.Second

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
	store       ReplayStore
	ttl         time.Duration
	maxAttempts uint32
	attempts    uint32
	mu          sync.Mutex
	bufPool     sync.Pool
}

func NewVerifier(maxAttempts uint32) *Verifier {
	return NewVerifierWithCapacity(maxAttempts, defaultMaxUsedCodes)
}

func NewVerifierWithCapacity(maxAttempts uint32, maxUsedCodes int) *Verifier {
	return NewVerifierWithStore(maxAttempts, NewInMemoryReplayStore(maxUsedCodes), defaultReplayTTL)
}

func NewVerifierWithStore(maxAttempts uint32, store ReplayStore, ttl time.Duration) *Verifier {
	v := &Verifier{
		store:       store,
		ttl:         ttl,
		maxAttempts: maxAttempts,
	}
	v.bufPool.New = func() any {
		return &replayBuf{bytes: make([]byte, 0, 128)}
	}
	return v
}

func (v *Verifier) VerifyWithReplayProtection(code, expected string) bool {
	return v.verifyInner(code, expected, nil, nil)
}

func (v *Verifier) VerifyWithContext(code, expected string, issuedContext, requestContext *OtpContext) bool {
	var issuedBytes, requestBytes []byte
	if issuedContext != nil {
		issuedBytes = issuedContext.Bytes()
	}
	if requestContext != nil {
		requestBytes = requestContext.Bytes()
	}
	return v.verifyInner(code, expected, issuedBytes, requestBytes)
}

func (v *Verifier) verifyInner(code, expected string, issuedContext, requestContext []byte) bool {

	v.mu.Lock()
	if v.attempts >= v.maxAttempts {
		v.mu.Unlock()
		return false
	}
	v.mu.Unlock()

	ctxMatch := constTimeEqBytes(issuedContext, requestContext)
	codeMatch := constantTimeEq(code, expected)

	if !ctxMatch || !codeMatch {
		v.mu.Lock()
		v.attempts++
		v.mu.Unlock()
		return false
	}

	b := v.bufPool.Get().(*replayBuf)
	b.bytes = b.bytes[:0]
	b.bytes = replayKey(b.bytes, code, issuedContext)

	firstSeen, err := v.store.CheckAndRecord(b.bytes, v.ttl)
	v.bufPool.Put(b)

	if err != nil {
		v.mu.Lock()
		v.attempts++
		v.mu.Unlock()
		return false
	}

	if !firstSeen {
		// Replay terdeteksi.
		//
		// Naikkan attempts secara sengaja tanpa ini ada bypass rate-limit. Skenario:
		//   maxAttempts=3. Attacker punya 1 OTP lama yang sudah masuk
		//   replay-set. Tanpa increment-on-replay, attacker bisa
		//   alternasi wrong -> replay -> wrong -> replay tanpa pernah kena
		//   rate-limit, karena replay dianggap "gratis".
		//
		// User legit tidak punya alasan mengirim kode yang sudah
		// di-mark used — itu sinyal aktivitas malicious yang pantas
		// dihukum rate limiter.
		v.mu.Lock()
		v.attempts++
		v.mu.Unlock()
		return false
	}

	v.mu.Lock()
	v.attempts = 0
	v.mu.Unlock()
	return true
}

func (v *Verifier) IsRateLimited() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.attempts >= v.maxAttempts
}

func (v *Verifier) ResetAttempts() {
	v.mu.Lock()
	v.attempts = 0
	v.mu.Unlock()
}

func (v *Verifier) ClearUsedCodes() {
	_ = v.store.Reset() //nolint:errcheck
}
