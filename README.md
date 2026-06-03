# genotp-go

[![CI](https://github.com/robby031/genotp-go/actions/workflows/ci.yml/badge.svg)](https://github.com/robby031/genotp-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/robby031/genotp-go)](https://goreportcard.com/report/github.com/robby031/genotp-go)
[![codecov](https://codecov.io/gh/robby031/genotp-go/branch/main/graph/badge.svg)](https://codecov.io/gh/robby031/genotp-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/robby031/genotp-go.svg)](https://pkg.go.dev/github.com/robby031/genotp-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Security-focused OTP library in Go. Full implementation of **HOTP (RFC 4226)** and **TOTP (RFC 6238)** plus advanced features: **context binding**, **per-context replay isolation**, and **clock skew detection**.

## Highlights

- ✅ Passes all RFC 4226 & RFC 6238 test vectors (SHA1/256/512)
- ✅ Replay protection + rate limiting with bounded memory
- ✅ Constant-time comparison to prevent timing attacks
- ✅ **Context binding** — OTP codes bound to (IP, device, session, origin)
- ✅ **Per-context replay isolation** — code collisions between users don't block each other
- ✅ **Anti-phishing origin binding** — origin URL automatically normalized
- ✅ **Clock skew detector** with opt-in auto-adjust
- ✅ Compatible with Google Authenticator / Authy / Microsoft Authenticator (default mode)
- ✅ Comprehensive test coverage

## Installation

```bash
go get github.com/robby031/genotp-go
```

## Basic Usage

### Standard TOTP (Google Authenticator compatible)

```go
package main

import (
    "fmt"
    "github.com/robby031/genotp-go"
)

func main() {
    secret, _ := genotp.CreateSecret()
    code, _ := genotp.GenTotpDefault(secret)
    valid, _ := genotp.VerifyTotpDefault(secret, code)
    
    fmt.Printf("Code: %s, Valid: %v\n", code, valid)
}
```

### Builder pattern (more ergonomic)

```go
secret, _ := genotp.CreateSecret()

totp, _ := genotp.NewTotpBuilder().
    Secret(secret).
    Algorithm(genotp.SHA1).
    Digits(6).
    Period(30).
    Build()

code, _ := totp.Generate(nil)
valid, _ := totp.Verify(code, nil, 1)
```

### QR code for authenticator app

```go
uri := genotp.NewOtpAuthUri(genotp.TotpType, "ACME:alice@example.com", genotp.EncodeBase32(secret)).
    Issuer("ACME").
    Algorithm(genotp.SHA1).
    Digits(6).
    Period(30).
    Build()

// Render `uri` to QR code (e.g., with a QR code library)
```

> **For comprehensive usage examples covering all features** — including HOTP/TOTP, builder/config patterns, context binding, verifier, clock skew detection, metrics, and production recommendations — see [`docs/usage.md`](docs/usage.md).

### Context binding — anti channel OTP intercept (flagship feature)

```go
hotp, _ := genotp.NewHOTP(secret, genotp.SHA1, 6)

// Server binds code to (session + IP hash) of user at issue time:
ctx := genotp.NewOtpContextBuilder().
    Session("login-abc123").
    IP("hash_of_user_ip").
    Build()

code, _ := hotp.GenBound(counter, ctx)
// Send `code` via any channel (SMS, email, WhatsApp, Telegram, push notif, ...).

// When user submits:
if hotp.VerifyBound(form.Code, counter, ctx) {
    // ✓ code correct AND context matches
}
// Attacker who intercepts code from different IP/session -> automatically rejected.
```

## Benchmarks
```text
go test ./tests -run=^$ -bench=. -benchmem
goos: darwin
goarch: arm64
pkg: github.com/robby031/genotp-go/tests
cpu: Apple M4
BenchmarkHOTPGenerate-10                         9545760               105.8 ns/op             8 B/op          1 allocs/op
BenchmarkHOTPVerify-10                          10859712               115.2 ns/op             0 B/op          0 allocs/op
BenchmarkTOTPGenerate-10                         9208617               132.3 ns/op             8 B/op          1 allocs/op
BenchmarkTOTPGenerateAtFixedTime-10             11921437               101.3 ns/op             8 B/op          1 allocs/op
BenchmarkTOTPVerify-10                           3929808               310.1 ns/op             0 B/op          0 allocs/op
BenchmarkTOTPVerifyWindow0-10                   12150944               101.0 ns/op             0 B/op          0 allocs/op
BenchmarkGenerateSecretDefault-10                6410404               188.3 ns/op            24 B/op          1 allocs/op
BenchmarkGenerateSecret256-10                    6637180               182.0 ns/op            32 B/op          1 allocs/op
BenchmarkBase32Encode-10                        62522793                19.37 ns/op           32 B/op          1 allocs/op
BenchmarkBase32Decode-10                        24413192                50.44 ns/op            0 B/op          0 allocs/op
BenchmarkProvisioningURITOTP-10                  3629484               331.1 ns/op           512 B/op         12 allocs/op
BenchmarkProvisioningURIHOTP-10                  3601312               332.0 ns/op           512 B/op         12 allocs/op
BenchmarkReplayProtectionVerify-10               5702733               242.2 ns/op             9 B/op          1 allocs/op
BenchmarkRateLimiterContention-10                 184306              6468 ns/op             112 B/op          5 allocs/op
BenchmarkConcurrentHOTPVerify-10                   43238             27402 ns/op             208 B/op          5 allocs/op
BenchmarkTOTPVerifyParallel-10                  69556314                16.51 ns/op            0 B/op          0 allocs/op
BenchmarkVerifierParallelFreshCodes-10           3175160               389.8 ns/op            10 B/op          1 allocs/op
PASS
ok      github.com/robby031/genotp-go/tests     24.131s
```

## Features

### HOTP (RFC 4226)

- Generate and verify HMAC-based One-Time Passwords
- Look-ahead resynchronization for counter drift
- Context binding for enhanced security

### TOTP (RFC 6238)

- Time-based One-Time Passwords with configurable period
- Window-based verification for clock skew tolerance
- Support for SHA1, SHA256, and SHA512 algorithms
- Context binding and clock skew tracking

### Context Binding

Bind OTP codes to specific contexts:
- IP address (or hash thereof)
- Device identifier
- Session ID
- Origin URL (anti-phishing)
- Custom fields

Two modes:
1. **HMAC binding**: Different contexts produce different OTP codes
2. **Verifier-stored**: Standard OTP codes, but server validates context

### Clock Skew Detection

Track and compensate for clock drift between client and server:
- Passive mode: only reports statistics
- Active mode: automatically adjusts verification window
- Recommends for window sizing or NTP sync

### Replay Protection

Prevent OTP code reuse with:
- Per-context replay isolation
- Configurable rate limiting
- Bounded memory usage

## API Reference

### Core Types

- `Algorithm`: SHA1, SHA256, SHA512
- `HOTP`: HMAC-based OTP implementation
- `TOTP`: Time-based OTP implementation
- `OtpContext`: Context binding data
- `ClockSkewDetector`: Clock drift tracking
- `Verifier`: Replay protection and rate limiting (per-instance)
- `ReplayStore`: pluggable backend untuk replay-set (default = in-memory
  bounded + TTL; untuk multi-replica deployment implement dengan Redis
  / etcd / sql — lihat [`docs/distributed_replay_protection.md`](docs/distributed_replay_protection.md))

### Helper Functions

- `CreateSecret()`: Generate a random 160-bit secret
- `GenHotpDefault()`: Generate HOTP with default parameters
- `GenTotpDefault()`: Generate TOTP with default parameters
- `VerifyHotpDefault()`: Verify HOTP with default parameters
- `VerifyTotpDefault()`: Verify TOTP with default parameters
- `EncodeBase32(data []byte) string`: Encode bytes to Base32 (RFC 4648, no padding)
- `DecodeBase32(dst []byte, src string) (int, error)`: Decode Base32 ke buffer
  caller. Strip ASCII whitespace, `-`, dan `=` otomatis. Mengembalikan
  jumlah byte yang ditulis. Returns `ErrDstTooSmall` jika `dst` kekecilan,
  `ErrInvalidSecret` jika ada karakter invalid.

## Testing

```bash
# Run all tests
go test ./tests

# Run tests with coverage
go test -v -race -coverprofile=coverage.out ./tests/

# Run fuzz tests (locally)
go test -fuzz=FuzzHOTPGenerate -fuzztime=1m ./fuzz/
go test -fuzz=FuzzTOTPVerify -fuzztime=1m ./fuzz/
```

All RFC test vectors are included and verified:
- RFC 4226 HOTP test vectors
- RFC 6238 TOTP test vectors (SHA1, SHA256, SHA512)

### Continuous Integration

The project uses GitHub Actions for automated testing on every push to `main` and pull requests:

**CI Workflow includes:**
- ✅ **Tests** - Run on Go 1.21, 1.22, and 1.23 with race detection
- ✅ **Fuzz Tests** - 30 seconds per fuzz target (10 fuzz functions total)
- ✅ **Linting** - golangci-lint with 15+ enabled linters
- ✅ **Security Scan** - gosec static analysis
- ✅ **Build Verification** - Ensures code compiles and go.mod is tidy
- ✅ **Code Coverage** - Uploaded to Codecov

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the full configuration.

## License

MIT — see [`LICENSE`](./LICENSE)
