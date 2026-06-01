package genotp

import (
	"sync"
	"time"
)

const defaultMaxUsedCodes = 10000

// defaultReplayTTL = period x (1 + 2xwindow) untuk TOTP standar
// (period=30, window=1). Kode TOTP berhenti valid setelah window kanan
// expired; replay entry tidak perlu lebih lama dari itu.
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

// NewVerifier membuat Verifier dengan InMemoryReplayStore default
// (10.000 entries, TTL 90 detik). Cocok untuk single-process /
// single-replica.
//
// **Untuk deployment multi-replica (Kubernetes, dll):** in-memory store
// TIDAK memberikan replay protection lintas replica — state pisah
// per-process. Pakai NewVerifierWithStore dengan implementasi
// ReplayStore yang shared (Redis SET NX EX, dll). Lihat
// docs/redis_replay_store.go.example.
func NewVerifier(maxAttempts uint32) *Verifier {
	return NewVerifierWithCapacity(maxAttempts, defaultMaxUsedCodes)
}

// NewVerifierWithCapacity sama dengan NewVerifier tapi memungkinkan
// override kapasitas in-memory store.
func NewVerifierWithCapacity(maxAttempts uint32, maxUsedCodes int) *Verifier {
	return NewVerifierWithStore(maxAttempts, NewInMemoryReplayStore(maxUsedCodes), defaultReplayTTL)
}

// NewVerifierWithStore membuat Verifier dengan ReplayStore custom dan
// TTL eksplisit. Dipakai untuk inject Redis / etcd / sql backend untuk
// distributed replay protection.
//
// **Catatan rate-limit (attempts counter):** masih per-instance, BUKAN
// distributed. Untuk distributed rate-limit, caller bertanggung jawab
// implement di layer di atas (mis. Redis INCR + EXPIRE di middleware
// gateway, atau pakai package rate-limit khusus). Library tidak
// mengabstraksi ini supaya scope tetap sempit.
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
	// Cek rate-limit duluan. Tidak terkunci sepanjang panggilan store
	// supaya backend distributed (Redis) tidak men-stall serialize.
	v.mu.Lock()
	if v.attempts >= v.maxAttempts {
		v.mu.Unlock()
		return false
	}
	v.mu.Unlock()

	// Constant-time match dijalankan SELALU sebelum store call:
	//   - Mencegah DoS attacker yang flood kode acak supaya store penuh.
	//   - Wrong code tidak menyentuh store sama sekali.
	//
	// Timing trade-off: code yang lolos match akan trigger satu store
	// roundtrip (~ms untuk Redis) — leak ke attacker "code Anda valid
	// structurally". Tapi response sudah memberikan {valid:bool} ke
	// caller, jadi tidak ada info tambahan dari timing.
	ctxMatch := constTimeEqBytes(issuedContext, requestContext)
	codeMatch := constantTimeEq(code, expected)

	if !ctxMatch || !codeMatch {
		v.mu.Lock()
		v.attempts++
		v.mu.Unlock()
		return false
	}

	// Build replay key (code + 0 + context) di stack-friendly buffer.
	b := v.bufPool.Get().(*replayBuf)
	b.bytes = b.bytes[:0]
	b.bytes = replayKey(b.bytes, code, issuedContext)

	firstSeen, err := v.store.CheckAndRecord(b.bytes, v.ttl)
	v.bufPool.Put(b)

	if err != nil {
		// Fail closed pada store error: lebih baik reject legit user
		// sekali daripada accept replay attacker. Increment attempts
		// supaya behavior konsisten dengan failure modes lain.
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

// ClearUsedCodes membersihkan replay-set. Untuk InMemoryReplayStore,
// drop semua entries. Untuk Redis backend, panggil pattern delete /
// FLUSHDB di implementor.
func (v *Verifier) ClearUsedCodes() {
	_ = v.store.Reset()
}
