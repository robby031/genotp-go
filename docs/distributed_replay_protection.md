# Distributed Replay Protection

`genotp-go` versi 1.x dengan sengaja TIDAK memasok backend distributed
out-of-the-box, supaya library tetap zero-dep. Tapi sejak versi yang
menambah `ReplayStore` interface, kamu bisa plug Redis / etcd / sql /
backend apa saja yang punya semantik **atomic check-and-set with TTL**.

## Mengapa default in-memory TIDAK aman di multi-replica

Skenario serangan:
1. Attacker dapat satu OTP valid `123456`, kirim ke LB.
2. Request di-route ke Pod A -> A catat di local map -> accept.
3. Attacker kirim ULANG `123456` -> LB route ke Pod B -> tidak ada di B -> **accept lagi**.
4. Effective replay bypass = N kali dengan N = jumlah replica.

`InMemoryReplayStore` (default) HANYA aman untuk:
- Single-process deployment
- Local development / testing
- Standalone CLI / desktop app

## Solusi: implementasikan `ReplayStore` dengan shared backend

```go
type ReplayStore interface {
    CheckAndRecord(key []byte, ttl time.Duration) (firstSeen bool, err error)
    Reset() error
}
```

Kunci-nya: `CheckAndRecord` HARUS atomic — kalau dua replica request
key yang sama bersamaan, tepat satu yang dapat `firstSeen=true`. Redis,
etcd, dan database modern semua punya primitif untuk ini.

## Contoh: Redis (paling umum)

`SET <key> 1 NX EX <ttl_seconds>` adalah satu round-trip, atomic.
Return value menunjukkan apakah key baru saja dibuat (NX = "set if Not
eXists").

```go
package myapp

import (
    "context"
    "time"
    "github.com/redis/go-redis/v9"
)

type RedisReplayStore struct {
    client *redis.Client
    prefix string
    ctx    context.Context
}

func NewRedisReplayStore(client *redis.Client, keyPrefix string) *RedisReplayStore {
    return &RedisReplayStore{
        client: client,
        prefix: keyPrefix,
        ctx:    context.Background(),
    }
}

func (s *RedisReplayStore) CheckAndRecord(key []byte, ttl time.Duration) (bool, error) {
    fullKey := s.prefix + ":" + string(key)
    // SetNX = SET <key> <val> NX EX <ttl>. Atomic across all clients.
    // Return true KALAU key baru di-create, false kalau sudah ada.
    ok, err := s.client.SetNX(s.ctx, fullKey, "1", ttl).Result()
    if err != nil {
        return false, err
    }
    return ok, nil
}

func (s *RedisReplayStore) Reset() error {
    // FLUSHDB tidak granular. Untuk production lebih baik pakai
    // SCAN + DEL dengan pattern <prefix>:* supaya tidak menyentuh data
    // lain di Redis yang sama.
    var cursor uint64
    for {
        keys, next, err := s.client.Scan(s.ctx, cursor, s.prefix+":*", 1000).Result()
        if err != nil {
            return err
        }
        if len(keys) > 0 {
            if err := s.client.Del(s.ctx, keys...).Err(); err != nil {
                return err
            }
        }
        if next == 0 {
            break
        }
        cursor = next
    }
    return nil
}
```

Pakai di Verifier:

```go
client := redis.NewClient(&redis.Options{Addr: "redis:6379"})
store := NewRedisReplayStore(client, "otp:replay")
verifier := genotp.NewVerifierWithStore(
    10,                  // maxAttempts
    store,
    90 * time.Second,    // TTL: period(30) x (1 + 2xwindow=1) = 90s
)
```

## Contoh: PostgreSQL

```sql
CREATE TABLE otp_replay (
    key TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX ON otp_replay (expires_at);
```

```go
func (s *PostgresReplayStore) CheckAndRecord(key []byte, ttl time.Duration) (bool, error) {
    // INSERT ... ON CONFLICT DO NOTHING returns rows affected.
    // Atomic + idempotent. Cleanup expired via cron job atau partial index.
    expiresAt := time.Now().Add(ttl)
    res, err := s.db.Exec(
        `INSERT INTO otp_replay (key, expires_at) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET expires_at = otp_replay.expires_at
         WHERE otp_replay.expires_at <= NOW()`,
        string(key), expiresAt,
    )
    if err != nil { return false, err }
    n, _ := res.RowsAffected()
    return n == 1, nil
}
```

(Optimal vacuum: scheduled `DELETE FROM otp_replay WHERE expires_at <= NOW()`.)

## Contoh: etcd

```go
func (s *EtcdReplayStore) CheckAndRecord(key []byte, ttl time.Duration) (bool, error) {
    lease, err := s.client.Grant(s.ctx, int64(ttl.Seconds()))
    if err != nil { return false, err }
    txn := s.client.Txn(s.ctx).If(
        clientv3.Compare(clientv3.CreateRevision(s.prefix+string(key)), "=", 0),
    ).Then(
        clientv3.OpPut(s.prefix+string(key), "1", clientv3.WithLease(lease.ID)),
    )
    resp, err := txn.Commit()
    if err != nil { return false, err }
    return resp.Succeeded, nil
}
```

## TTL pemilihan

Untuk TOTP standar (`period=30s`, `window=1`):
```
TTL = period x (1 + 2xwindow) = 30 x 3 = 90 detik
```

Karena kode di counter T bisa accept di T-1, T, T+1 (3 window), validity
real-time-nya = 90 detik. Setelah itu, kode otomatis invalid karena
counter-nya sudah lewat — replay-set tidak perlu menahannya lagi.

Untuk HOTP (counter-based, tanpa time), pakai TTL panjang (jam-hari)
atau tidak pakai TTL sama sekali (gunakan tombstone permanen). HOTP
counter bergerak dengan kecepatan user.

Untuk TOTP dengan window=2:
```
TTL = 30 x 5 = 150 detik
```

## Rate-limit di multi-replica

Library hanya provide replay-store interface. **Attempts counter masih
per-instance, in-memory** — sama masalahnya dengan map asli. Untuk
distributed rate-limit:

1. Pakai package external (Redis token bucket) di middleware gateway
   SEBELUM panggil Verifier. Itu sebenarnya cara yang lebih baik karena
   rate-limit memang concern infrastructure, bukan crypto library.
2. Atau ignore Verifier's `IsRateLimited()` dan andalkan ratelimiter
   middleware Anda sendiri.

Pseudo-kode middleware:

```go
func RateLimitMiddleware(next http.Handler) http.Handler {
    limiter := redisrate.New(redisClient, ...)
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !limiter.Allow(r.RemoteAddr) {
            http.Error(w, "rate limited", 429)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

## Failure mode: backend down

`CheckAndRecord` mengembalikan error kalau backend mati. Verifier
memperlakukan ini sebagai **fail closed** — kode ditolak, attempts
naik. Ini intentional:

- Fail open (accept saat backend down) memungkinkan replay attack saat
  Redis sedang down -> tidak acceptable.
- Fail closed memunculkan UX issue (user gak bisa login saat Redis
  down) -> bisa, tapi defense-in-depth lewat circuit breaker /
  fallback policy bisa ditangani di layer atas (mis. tolak auth
  sementara, redirect ke flow recovery, monitor uptime).

Trade-off ini disengaja di library — security > availability untuk
crypto verify path.
