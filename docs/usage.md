# Usage Guide

This guide provides practical examples for every feature in genotp-go, organized from simple to advanced. All examples use standard international English and match the actual library API.

## Table of Contents

- [Secret Generation](#secret-generation)
- [HOTP (Counter-Based)](#hotp-counter-based)
- [TOTP (Time-Based)](#totp-time-based)
- [Builder Pattern](#builder-pattern)
- [Config Pattern](#config-pattern)
- [Base32 Encoding](#base32-encoding)
- [Provisioning URI](#provisioning-uri)
- [Context Binding](#context-binding)
- [Secret Providers](#secret-providers)
- [HMAC Providers](#hmac-providers)
- [Verifier (Replay & Rate Limiting)](#verifier-replay--rate-limiting)
- [Clock Skew Detection](#clock-skew-detection)
- [Metrics](#metrics)
- [Production Recommendations](#production-recommendations)

---

## Secret Generation

Always use `crypto/rand`-backed functions. Never generate OTP secrets with `math/rand`.

### Default Secret (160-bit)

```go
secret, err := genotp.CreateSecret()
if err != nil {
    log.Fatal(err)
}
```

### Custom Length (minimum 128 bits)

```go
kg := &genotp.KeyGen{}

// 256-bit secret (32 bytes)
secret, err := kg.GenerateSecret(256)
if err != nil {
    log.Fatal(err)
}

// Or fill an existing buffer
buf := make([]byte, 32)
if err := kg.FillSecret(buf); err != nil {
    log.Fatal(err)
}
```

### Recommended Pattern

Persist the secret encrypted at rest. Call `ClearSecret()` on `HOTP` / `TOTP` instances when they are no longer needed.

---

## HOTP (Counter-Based)

### Basic Generate and Verify

```go
secret, _ := genotp.CreateSecret()

hotp, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
if err != nil {
    log.Fatal(err)
}

counter := uint64(0)

// Generate
code, err := hotp.Generate(counter)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Code:", code)

// Verify
ok, err := hotp.Verify(code, counter)
if err != nil {
    log.Fatal(err)
}
if ok {
    fmt.Println("Valid")
}
```

### Look-Ahead Resynchronization

Use this when the client counter may have drifted ahead (e.g., user pressed the button multiple times without verifying).

```go
matchedCounter, ok, err := hotp.VerifyWithResync(code, serverCounter, 10)
if err != nil {
    log.Fatal(err)
}
if ok {
    fmt.Printf("Matched at counter %d\n", matchedCounter)
    // Update serverCounter to matchedCounter + 1
}
```

### Context-Bound HOTP

Bind the OTP to a specific session or device. An attacker who intercepts the code cannot use it from a different context.

```go
ctx := genotp.NewOtpContextBuilder().
    Session("sess-abc123").
    IP("192.168.1.100").
    Build()

code, err := hotp.GenBound(counter, ctx)
if err != nil {
    log.Fatal(err)
}

// Later, verify with the same context
ok, err := hotp.VerifyBound(userCode, counter, ctx)
```

### Clear Secret from Memory

```go
hotp.ClearSecret()
```

---

## TOTP (Time-Based)

### Basic Generate and Verify

```go
secret, _ := genotp.CreateSecret()

totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
if err != nil {
    log.Fatal(err)
}

// Generate using current time
code, err := totp.Generate(nil)
if err != nil {
    log.Fatal(err)
}

// Verify with a window of 1 period (current +/- 30s)
ok, err := totp.Verify(code, nil, 1)
if err != nil {
    log.Fatal(err)
}
```

### Verify at a Fixed Time

```go
fixedTime := uint64(1728000000) // Unix timestamp
code, _ := totp.Generate(&fixedTime)
ok, _ := totp.Verify(code, &fixedTime, 0)
```

### Context-Bound TOTP

```go
ctx := genotp.NewOtpContextBuilder().
    Device("device-xyz").
    Origin("https://example.com").
    Build()

code, _ := totp.GenBound(ctx, nil)
ok, _ := totp.VerifyBound(userCode, ctx, nil, 1)
```

### Coarse Location Context

Prefer coarse, application-defined location labels instead of raw GPS
coordinates. This improves stability and keeps OTP verification resilient to
location jitter.

```go
ctx := genotp.NewOtpContextBuilder().
    Session("login-abc123").
    Region("id-lmg-bluluk").
    GeoBucket("grid-a1").
    DistanceClass(genotp.DistanceClassNearby).
    Build()

code, _ := totp.GenBound(ctx, nil)
ok, _ := totp.VerifyBound(userCode, ctx, nil, 1)
```

Valid distance classes are:
- `genotp.DistanceClassSameArea`
- `genotp.DistanceClassNearby`
- `genotp.DistanceClassFar`

---

## Secret Providers

Use a `SecretProvider` when your application stores OTP secrets in wrapped or
externally-managed form and only wants to resolve them at the moment of use.

```go
provider := genotp.SecretProviderFunc(func() ([]byte, error) {
    // Example: decrypt with KMS, unwrap from HSM-adjacent storage,
    // or fetch from an external secret manager.
    return loadUserSecret()
})

totp, err := genotp.NewTOTPFromSecretProvider(provider, genotp.SHA256, 6, 30)
if err != nil {
    log.Fatal(err)
}

code, err := totp.Generate(nil)
if err != nil {
    log.Fatal(err)
}
```

Notes:
- This is an additive API. Existing `NewHOTP(...)` and `NewTOTP(...)` flows are unchanged.
- In this v1 model, the provider resolves secret bytes per OTP operation.
- Temporary secret buffers are zeroed after use.
- This is best suited for wrapped-secret / KMS-unlock flows.
- A future `HMACProvider` style abstraction can support true non-exportable HSM-backed keys without changing this API.

---

## HMAC Providers

Use an `HMACProvider` when the OTP key must remain non-exportable and all HMAC
operations must be delegated to an HSM, KMS-native MAC API, or remote signing
service.

```go
provider := genotp.HMACProviderFunc(func(algorithm genotp.Algorithm, message []byte) ([]byte, error) {
    return signWithHSM(algorithm, message)
})

hotp, err := genotp.NewHOTPFromHMACProvider(provider, genotp.SHA1, 6)
if err != nil {
    log.Fatal(err)
}

code, err := hotp.Generate(42)
if err != nil {
    log.Fatal(err)
}
```

Notes:
- This is an additive API. Existing constructors and `SecretProvider` mode are unchanged.
- The library never resolves raw secret bytes in this mode.
- The provider must return a full HMAC output matching the requested algorithm.
- This is the preferred path for true non-exportable HSM-backed OTP keys.

See [`provider_adapters.md`](provider_adapters.md) for concrete adapter
patterns such as AWS KMS decrypt-backed `SecretProvider` and Vault Transit
`HMACProvider`.

### Clock Skew Tracking

See the [Clock Skew Detection](#clock-skew-detection) section for the recommended pattern.

---

## Builder Pattern

Use builders when you want a fluent, readable configuration.

### HOTP Builder

```go
secret, _ := genotp.CreateSecret()

hotp, err := genotp.NewHotpBuilder().
    Secret(secret).
    Algorithm(genotp.SHA256).
    Digits(6).
    Build()
if err != nil {
    log.Fatal(err)
}
```

### TOTP Builder

```go
totp, err := genotp.NewTotpBuilder().
    Secret(secret).
    Algorithm(genotp.SHA256).
    Digits(6).
    Period(30).
    Build()
if err != nil {
    log.Fatal(err)
}
```

---

## Config Pattern

Use configs when you want to predefine settings and reuse them.

```go
// Predefine a config
cfg := genotp.NewTotpConfig().
    WithAlgorithm(genotp.SHA256).
    WithDigits(6).
    WithPeriod(30)

// Instantiate multiple TOTPs from the same config
for _, secret := range userSecrets {
    totp, err := genotp.NewTotpFromConfig(secret, cfg)
    if err != nil {
        continue
    }
    // use totp ...
}
```

---

## Base32 Encoding

The library provides RFC 4648 Base32 encoding without padding. This is the standard format used by authenticator apps.

```go
secret, _ := genotp.CreateSecret()

// Encode for QR code / manual entry
encoded := genotp.EncodeBase32(secret)
fmt.Println(encoded) // e.g., "JBSWY3DPEHPK3PXP"

// Decode back to bytes
dst := make([]byte, 64)
n, err := genotp.DecodeBase32(dst, encoded)
if err != nil {
    log.Fatal(err)
}
decoded := dst[:n]
```

`DecodeBase32` automatically strips whitespace, hyphens, and padding characters.

---

## Provisioning URI

Generate `otpauth://` URIs for authenticator apps.

### TOTP URI

```go
secret, _ := genotp.CreateSecret()
b32 := genotp.EncodeBase32(secret)

uri := genotp.NewOtpAuthUri(genotp.TotpType, "ACME:alice@example.com", b32).
    Issuer("ACME").
    Algorithm(genotp.SHA1).
    Digits(6).
    Period(30).
    Build()

fmt.Println(uri)
// otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30
```

### HOTP URI

```go
uri := genotp.NewOtpAuthUri(genotp.HotpType, "ACME:alice@example.com", b32).
    Issuer("ACME").
    Algorithm(genotp.SHA1).
    Digits(6).
    Counter(0).
    Build()
```

---

## Context Binding

Context binding prevents phishing and replay by coupling an OTP to a specific environment.

### Building a Context

```go
ctx := genotp.NewOtpContextBuilder().
    IP(clientIP).
    Device(deviceID).
    Session(sessionID).
    Origin("https://example.com").
    Custom("team", "engineering").
    Build()
```

Origin normalization is automatic: scheme + host only, lowercased, with query, fragment, and trailing slash removed.

### Two Modes of Context Binding

1. **HMAC binding** (`GenBound` / `VerifyBound`): The context bytes are mixed into the HMAC. The same secret + counter + different context yields a completely different code.
2. **Verifier-stored** (`VerifyWithContext`): The code is standard, but the server validates the context match before accepting.

Use HMAC binding when you want the code itself to be context-sensitive. Use verifier-stored when you need standard codes that must also pass a context check on the server.

---

## Verifier (Replay & Rate Limiting)

`Verifier` is the recommended way to validate OTPs in production. It adds replay protection and rate limiting on top of the basic code match.

### Basic Usage

```go
verifier := genotp.NewVerifier(5) // max 5 failed attempts

// expectedCode comes from your HOTP/TOTP.Generate
ok := verifier.VerifyWithReplayProtection(userCode, expectedCode)
if !ok {
    if verifier.IsRateLimited() {
        fmt.Println("Too many attempts. Try again later.")
    } else {
        fmt.Println("Invalid or reused code.")
    }
}
```

### With Context

```go
ctx := genotp.NewOtpContextBuilder().IP(clientIP).Build()

ok := verifier.VerifyWithContext(userCode, expectedCode, ctx, ctx)
```

### Per-User Verifier Instances

In a web application, create one `Verifier` per user session or account. Store it in a map or cache keyed by user ID.

```go
type UserSession struct {
    Verifier *genotp.Verifier
    Secret   []byte
}

// On login attempt
session := sessions[userID]
expected, _ := totp.Generate(nil)

ok := session.Verifier.VerifyWithReplayProtection(userCode, expected)
if ok {
    session.Verifier.ResetAttempts()
}
```

### Multi-Replica Deployment

`NewVerifier` uses an in-memory replay store. For multi-replica deployments (Kubernetes, ECS, etc.), provide a distributed backend.

```go
// Implement genotp.ReplayStore with Redis SET NX EX
distributedStore := NewRedisReplayStore(redisClient)
verifier := genotp.NewVerifierWithStore(
    5,                      // max attempts
    distributedStore,       // shared across replicas
    90*time.Second,         // replay TTL
)
```

See [`distributed_replay_protection.md`](distributed_replay_protection.md) for a Redis implementation example.

---

## Clock Skew Detection

Use `ClockSkewDetector` to detect and compensate for time drift between the client device and the server.

### Basic Usage

```go
totp, _ := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
detector := genotp.NewClockSkewDetector(64)

ok, _ := totp.VerifyTracking(userCode, nil, 1, detector)
if ok {
    report := detector.Report()
    fmt.Printf("Mean offset: %.2f periods\n", report.MeanOffset)
    fmt.Printf("Recommendation: %s\n", report.Recommend)
}
```

### Auto-Adjust Mode

```go
detector := genotp.NewClockSkewDetector(64)
detector.EnableAutoAdjust()

// After enough samples (>= 16), the detector automatically compensates
ok, _ := totp.VerifyTracking(userCode, nil, 1, detector)
```

### Monitoring

```go
report := detector.Report()

switch report.Recommend {
case genotp.ConsistentDrift:
    log.Println("Client clock is drifting. Consider widening the window.")
case genotp.WidenWindowOrCheckNtp:
    log.Println("Many edge hits. Check NTP sync or increase window.")
case genotp.NoActionNeeded:
    // Everything is fine
case genotp.InsufficientData:
    // Not enough samples yet
}
```

---

## Metrics

Track generation and verification counts for observability.

```go
metrics := genotp.NewMetrics()

// In your HOTP/TOTP wrapper
func (s *Service) GenerateTOTP(secret []byte) (string, error) {
    code, err := s.totp.Generate(nil)
    if err != nil {
        metrics.IncrementError()
        return "", err
    }
    metrics.IncrementTotpGeneration()
    return code, nil
}

func (s *Service) VerifyTOTP(secret []byte, code string) (bool, error) {
    ok, err := s.totp.Verify(code, nil, 1)
    if err != nil {
        metrics.IncrementError()
        return false, err
    }
    if ok {
        metrics.IncrementTotpVerification()
    }
    return ok, nil
}

// Read metrics
fmt.Printf("Generations: %d\n", metrics.GetTotpGenerations())
fmt.Printf("Verifications: %d\n", metrics.GetTotpVerifications())
fmt.Printf("Errors: %d\n", metrics.GetErrors())
```

---

## Production Recommendations

### 1. Always Handle Errors

Never ignore errors from constructors or methods. Invalid secrets, algorithms, or counters return concrete errors.

```go
hotp, err := genotp.NewHOTP(secret, algo, digits)
if err != nil {
    return fmt.Errorf("init HOTP: %w", err)
}
```

### 2. Use a Verifier in Production

Never rely solely on `Verify()`. Always wrap verification with `Verifier` for replay protection and rate limiting.

### 3. Encrypt Secrets at Rest

Store secrets encrypted in your database. Decrypt only when needed for generation or verification.

### 4. Per-User Verifier Instances

Do not share a single `Verifier` across all users. Create one per user or session to prevent cross-user rate-limit interference.

### 5. Distributed Replay Store

If you run multiple server instances, use `NewVerifierWithStore` with Redis, etcd, or SQL as the backend.

### 6. Context Binding for Sensitive Flows

For high-security flows (banking, admin panels), use `GenBound` / `VerifyBound` or `VerifyWithContext` to bind codes to IP + device + origin.

### 7. Clear Secrets from Memory

Call `ClearSecret()` when an `HOTP` / `TOTP` instance is no longer needed. Note that Go's garbage collector may retain memory pages; for extreme security, manage secret lifetimes with `sync.Pool` or pinned buffers.

### 8. Prefer SHA256 or SHA512

SHA1 is the default for compatibility with older authenticator apps. For new systems, prefer `SHA256` or `SHA512`.

```go
totp, _ := genotp.NewTOTP(secret, genotp.SHA256, 6, 30)
```

### 9. Monitor with Metrics

Export `Metrics` to your monitoring stack (Prometheus, StatsD, etc.) to detect anomalies in OTP generation or verification rates.
