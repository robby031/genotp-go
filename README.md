# genotp-go

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
// Attacker who intercepts code from different IP/session → automatically rejected.
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
- `Verifier`: Replay protection and rate limiting

### Helper Functions

- `CreateSecret()`: Generate a random 160-bit secret
- `GenHotpDefault()`: Generate HOTP with default parameters
- `GenTotpDefault()`: Generate TOTP with default parameters
- `VerifyHotpDefault()`: Verify HOTP with default parameters
- `VerifyTotpDefault()`: Verify TOTP with default parameters
- `EncodeBase32()`: Encode bytes to Base32
- `DecodeBase32()`: Decode Base32 to bytes

## Testing

```bash
go test ./tests
```

All RFC test vectors are included and verified:
- RFC 4226 HOTP test vectors
- RFC 6238 TOTP test vectors (SHA1, SHA256, SHA512)

## License

MIT — see [`LICENSE`](./LICENSE)
