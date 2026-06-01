package genotp

import (
	"sync"
	"time"
)

// ReplayStore abstrak penyimpanan kode OTP yang sudah pernah diterima.
//
// **Kenapa interface dan bukan map biasa di Verifier:** library ini
// dirancang bisa dipakai di mode single-process (cukup InMemoryReplayStore)
// dan distributed (multi-replica di belakang load balancer). Tanpa
// abstraksi backend, replay protection pecah secara halus di lingkungan
// distributed:
//
//	Server A | Server B | Server C  <- 3 replika di belakang LB
//	  RAM     |   RAM    |   RAM    <- state TERPISAH per proses
//
// Skenario serangan nyata:
//  1. Attacker dapat 1 OTP valid, kirim ke LB -> di-route ke Server A.
//  2. Server A.usedCodes catat -> accept.
//  3. Attacker kirim ULANG kode yang sama -> kali ini di-route ke Server B.
//  4. Server B.usedCodes kosong (state tidak ter-replikasi) -> accept lagi.
//  5. Effective replay bypass = N kali, dengan N = jumlah replica.
//
// Solusi: implementasikan ReplayStore dengan storage shared (Redis SET NX
// EX, etcd lease, sql + unique constraint, dll) supaya semua replica
// melihat state yang sama. Library kasih default in-memory yang aman
// untuk single-process; production deploy multi-replica WAJIB pakai
// distributed backend. Lihat docs/redis_example untuk contoh.
type ReplayStore interface {
	// CheckAndRecord mengembalikan true KALAU `key` belum pernah dicatat
	// dalam window TTL-nya (firstSeen). Atomic: kalau dua caller paralel
	// (atau dua replica) memanggil dengan key yang sama bersamaan, tepat
	// satu yang mendapat firstSeen=true.
	//
	// `ttl` = berapa lama key tetap menolak resubmission. Untuk TOTP
	// pilih period x (1 + 2xwindow). Mis. period=30, window=1 -> ttl=90s
	// supaya kode yang valid di counter T-1 ditolak sampai jendela
	// validitas alaminya lewat.
	//
	// Error backend (Redis down, network timeout) di-propagate via err;
	// caller (Verifier) memperlakukan error sebagai "fail closed" — kode
	// ditolak. Lebih baik false negative daripada bypass.
	CheckAndRecord(key []byte, ttl time.Duration) (firstSeen bool, err error)

	// Reset menghapus semua entries. Dipakai oleh testing dan admin
	// reset. Backend distributed bisa FLUSHDB / namespaced delete.
	Reset() error
}

// InMemoryReplayStore adalah default impl — bounded map dengan TTL.
//
// **Anti-amnesia:** versi lama Verifier melakukan `map = make(...)` saat
// penuh, yang menyebabkan SEMUA kode lama tiba-tiba kembali valid. Itu
// kelemahan yang bisa dieksploitasi attacker yang tahu cap-nya: flood
// dengan kode acak supaya cap terlampaui -> semua kode bekas yang dia
// pernah intercept jadi bisa di-replay lagi.
//
// Implementasi ini ganti pola itu dengan:
//  1. Sweep periodik (~tiap 30s) untuk reclaim entries yang sudah expired.
//  2. Saat cap-hit, evict 10% entries acak (bukan clear-all). Worst case
//     attacker bisa men-displace 10% entries terlama, bukan 100%.
//
// Pilihan batch 10% acak (vs O(n) eviction per entry tertua):
//   - Map iteration di Go acak per range -> setara random eviction tanpa
//     overhead LRU list.
//   - Amortized O(1) per CheckAndRecord call: setelah evict 10%, ada
//     ruang 10% sebelum trigger eviction lagi -> cost terbagi merata.
//   - 90% entries bertahan dari setiap eviction -> defense-in-depth
//     terhadap amnesia tetap kuat.
//
// Kompleksitas:
//   - CheckAndRecord: O(1) amortized, O(0.1n) worst case saat cap-hit.
//   - Memory: bounded di maxSize entries x ~100 byte/key worst case.
type InMemoryReplayStore struct {
	mu         sync.Mutex
	entries    map[string]int64 // key -> expiry unixNano
	maxSize    int
	nextSweep  time.Time
	sweepEvery time.Duration
}

// NewInMemoryReplayStore membuat store dengan kapasitas maxSize entries.
// Sweep periodik dilakukan ~tiap 30 detik. Untuk OTP workload normal,
// maxSize 10.000 menampung beberapa menit traffic, cukup untuk TTL OTP
// (~90 detik).
func NewInMemoryReplayStore(maxSize int) *InMemoryReplayStore {
	return &InMemoryReplayStore{
		entries:    make(map[string]int64),
		maxSize:    maxSize,
		sweepEvery: 30 * time.Second,
	}
}

func (s *InMemoryReplayStore) CheckAndRecord(key []byte, ttl time.Duration) (bool, error) {
	now := time.Now()
	nowNano := now.UnixNano()
	expireAt := nowNano + ttl.Nanoseconds()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Sweep periodik untuk reclaim entries expired tanpa nunggu cap-hit.
	if now.After(s.nextSweep) {
		s.sweepExpiredLocked(nowNano)
		s.nextSweep = now.Add(s.sweepEvery)
	}

	// Cek presence dulu — kalau ada dan belum expired, ini replay.
	// String conversion di sini alokasi 1x per call; tidak bisa dihindari
	// karena Go map key tidak bisa []byte. Pool replayBuf di Verifier
	// memberi setengah amortization.
	keyStr := string(key)
	if exp, ok := s.entries[keyStr]; ok && exp > nowNano {
		return false, nil
	}

	// Kapasitas penuh: sweep dulu (mungkin ada yang baru expired sejak
	// sweep periodik terakhir). Kalau masih penuh, batch-evict 10%
	// secara acak (random map iteration order). Tidak pernah clear-all.
	if len(s.entries) >= s.maxSize {
		s.sweepExpiredLocked(nowNano)
		if len(s.entries) >= s.maxSize {
			s.evictBatchLocked()
		}
	}

	s.entries[keyStr] = expireAt
	return true, nil
}

func (s *InMemoryReplayStore) sweepExpiredLocked(nowNano int64) {
	for k, exp := range s.entries {
		if exp <= nowNano {
			delete(s.entries, k)
		}
	}
}

// evictBatchLocked menghapus ~10% entries (minimal 1). Pakai map
// iteration acak Go sebagai random-eviction tanpa overhead struktur
// data tambahan. Setelah evict, ada ruang ~10% sebelum cap-hit
// berikutnya -> amortized O(1) per insert.
func (s *InMemoryReplayStore) evictBatchLocked() {
	target := max(len(s.entries)/10, 1)
	count := 0
	for k := range s.entries {
		delete(s.entries, k)
		count++
		if count >= target {
			return
		}
	}
}

func (s *InMemoryReplayStore) Reset() error {
	s.mu.Lock()
	s.entries = make(map[string]int64)
	s.nextSweep = time.Time{}
	s.mu.Unlock()
	return nil
}

// Size mengembalikan jumlah entries aktif (termasuk yang sudah expired
// tapi belum disweep). Buat introspeksi / metrics.
func (s *InMemoryReplayStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
