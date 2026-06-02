# Security Considerations

This document outlines security considerations and best practices when using the genotp-go library.

## Table of Contents

- [Secret Key Management](#secret-key-management)
- [Memory Safety](#memory-safety)
- [Timing Attacks](#timing-attacks)
- [Replay Protection](#replay-protection)
- [Rate Limiting](#rate-limiting)
- [Clock Skew Detection](#clock-skew-detection)
- [Context Binding](#context-binding)
- [Algorithm Selection](#algorithm-selection)
- [URI Security](#uri-security)
- [Best Practices](#best-practices)
- [Reporting Vulnerabilities](#reporting-vulnerabilities)

## Secret Key Management

### Generation

The library uses `crypto/rand` from the Go standard library to generate secrets. `crypto/rand` calls the OS-provided CSPRNG: `getrandom(2)` on Linux, `arc4random` on macOS/BSD, and `BCryptGenRandom` on Windows.

```go
import "github.com/robby031/genotp-go"

// Generate a default 160-bit (20-byte) secret
secret, err := genotp.CreateSecret()

// Or with a custom length (minimum 128 bits)
kg := &genotp.KeyGen{}
secret, err := kg.GenerateSecret(256)
```

- **Minimum Key Length**: Use at least 128-bit (16-byte) secrets for HOTP/TOTP
- **Recommended Key Length**: Use 256-bit (32-byte) secrets for better security
- **Never Reuse Secrets**: Each user/service should have a unique secret

### Storage

- **Encrypt at Rest**: Store secrets encrypted in your database
- **Use a KMS**: Consider using a Key Management Service for managing encryption keys
- **Access Control**: Restrict access to secrets to authorized personnel only
- **Audit Logs**: Log all access to secret keys

### Transmission

- **Use HTTPS**: Always transmit secrets over encrypted connections
- **Avoid Email**: Never send secrets via email or other insecure channels
- **Secure Channels**: Use secure channels for initial secret provisioning

## Memory Safety

### ClearSecret

`HOTP` and `TOTP` provide a `ClearSecret()` method that explicitly overwrites the secret with zeros. Unlike Rust, Go does not have automatic destructors, so the caller must invoke `ClearSecret()` manually.

```go
hotp, _ := genotp.NewHOTP(secret, genotp.SHA1, 6)
// ... use hotp ...
hotp.ClearSecret() // Secret is overwritten with zeros
```

**Important note on the Go GC**: The Go garbage collector does not guarantee timely deallocation. Secrets may remain in memory until the next GC cycle or until the page is reused. For high-security requirements, consider managing secrets with `sync.Pool` or pinned memory.

### Implementation Details

- **Manual Zeroize**: `ClearSecret()` performs a byte-by-byte overwrite loop
- **Cleared Flag**: The struct carries an atomic `cleared` flag; operations after clearing will fail
- **No Persistence**: Secrets are never written to disk or logs by the library

## Timing Attacks

### Constant-Time Comparison

The library implements constant-time comparison internally. All `Verify` and `VerifyWithResync` methods on `HOTP`, as well as `Verify`, `VerifyBound`, and `VerifyTracking` on `TOTP`, automatically use constant-time comparison.

```go
hotp, _ := genotp.NewHOTP(secret, genotp.SHA1, 6)
ok, _ := hotp.Verify(code, counter) // internal constant-time comparison
```

### Protection Against

- **Timing Side Channels**: Code comparison time is independent of the input
- **No Early Returns**: Comparison completes even after a mismatch is detected
- **Fixed-Time Operations**: All operations take the same amount of time regardless of input

## Replay Protection

### Built-in Features

The library provides replay protection through the `Verifier` struct:

```go
verifier := genotp.NewVerifier(5) // max 5 attempts
ok := verifier.VerifyWithReplayProtection(code, expected)
```

### Verifier with Context

For stronger protection, use context binding:

```go
ctx := genotp.NewOtpContextBuilder().IP(clientIP).Device(deviceID).Build()
ok := verifier.VerifyWithContext(code, expected, issuedCtx, requestCtx)
```

### How It Works

- **Code Tracking**: `ReplayStore` records codes that have already been accepted
- **TTL**: Entries automatically expire after the TTL (default 90 seconds)
- **Fail Closed**: Store errors (e.g., Redis down) are treated as reject, not accept

### Multi-Replica Deployment

**Warning**: `NewVerifier` uses an `InMemoryReplayStore` that is only safe for single-process deployments. In a multi-replica environment (e.g., Kubernetes), replay state is isolated per process, and an attacker can bypass replay protection by routing the same code to a different replica.

**Solution**: Use `NewVerifierWithStore` with a shared backend:

```go
// Implement ReplayStore with Redis SET NX EX
distributedStore := NewRedisReplayStore(redisClient)
verifier := genotp.NewVerifierWithStore(5, distributedStore, 90*time.Second)
```

## Rate Limiting

### Built-in Features

The `Verifier` provides rate limiting based on an attempt counter:

```go
verifier := genotp.NewVerifier(5)
if verifier.IsRateLimited() {
    // reject the request, return 429 or lock out the user
}
ok := verifier.VerifyWithReplayProtection(code, expected)
```

### Reset and Monitoring

```go
verifier.ResetAttempts()        // Reset the counter (e.g., after secondary authentication)
verifier.ClearUsedCodes()       // Clear the replay set (admin/testing)
```

### Limitations

The attempt-based rate limiting is **per-instance**, not distributed. For multi-replica deployments, implement distributed rate limiting at the gateway layer (e.g., Redis INCR + EXPIRE).

## Clock Skew Detection

The library supports clock-skew detection and compensation for TOTP:

```go
detector := genotp.NewClockSkewDetector(64)
detector.EnableAutoAdjust()

ok, _ := totp.VerifyTracking(code, nil, 1, detector)
report := detector.Report()
// report.Recommend provides guidance such as ConsistentDrift, WidenWindowOrCheckNtp, etc.
```

- **Clock Skew**: Compensates for time drift between the client and the server
- **Auto Adjust**: Automatically adjusts the offset based on verification history
- **Edge Hit Detection**: Detects whether the user frequently lands at the edge of the window

## Context Binding

Context binding ties an OTP to a specific context (IP, device, origin) to prevent phishing and replay in a different environment:

```go
ctx := genotp.NewOtpContextBuilder().
    IP(clientIP).
    Device(deviceID).
    Origin("https://example.com").
    Build()

code, _ := totp.GenBound(ctx, nil)
ok, _ := totp.VerifyBound(userCode, ctx, nil, 1)
```

- **Phishing Resistance**: A code is only valid for the matching context
- **Reusable with Verifier**: `VerifyWithContext` compares the context before the replay check

## Algorithm Selection

### Supported Algorithms

- **SHA1**: The default, widely supported by clients, but consider it deprecated for new systems
- **SHA256**: Recommended for new implementations
- **SHA512**: The highest security level, but may not be supported by all clients

### Recommendations

- **Use SHA256+**: Prefer SHA256 or SHA512 for new implementations
- **Check Client Support**: Verify that the client supports the chosen algorithm
- **Plan Migration**: Have a migration plan if you are currently using SHA1

### Performance Considerations

- **SHA1**: The fastest, but the least secure
- **SHA256**: A good balance of speed and security
- **SHA512**: Slower, but the most secure

## URI Security

### otpauth:// URIs

The library generates `otpauth://` URIs for provisioning:

```go
uri := genotp.NewOtpAuthUri(genotp.TotpType, "Service:user@example.com", secretB32).
    Issuer("Example Inc").
    Algorithm(genotp.SHA256).
    Digits(6).
    Period(30).
    Build()
```

### Security Considerations

- **Secret in URI**: The secret is included in the URI (required by the standard)
- **Transmission**: Use QR codes or secure channels for URI transmission
- **Short Lifetime**: Generate URIs with a short expiration when possible
- **Access Control**: Restrict who can generate and view URIs

### Best Practices

- **HTTPS Only**: Never transmit URIs over unencrypted connections
- **QR Code Security**: Display QR codes securely, not in public areas
- **One-Time Use**: Generate a new URI for each provisioning event
- **Audit Logging**: Log URI generation events

## Best Practices

### General

1. **Use the Latest Version**: Always use the latest version of the library
2. **Keep Dependencies Updated**: Update dependencies regularly
3. **Security Audits**: Perform regular security audits
4. **Penetration Testing**: Conduct penetration testing
5. **Code Review**: Have code reviewed by security experts

### Implementation

1. **Validate Input**: Always validate user input
2. **Error Handling**: Implement proper error handling
3. **Logging**: Log security-relevant events
4. **Monitoring**: Monitor for suspicious activity
5. **Incident Response**: Have an incident response plan

### Deployment

1. **Environment Separation**: Separate development, staging, and production
2. **Access Control**: Implement proper access controls
3. **Network Security**: Use firewalls and network segmentation
4. **Regular Backups**: Maintain regular, secure backups
5. **Disaster Recovery**: Have a disaster recovery plan

## Reporting Vulnerabilities

### How to Report

If you discover a security vulnerability, please report it responsibly via the GitHub issue tracker or by contacting the maintainer.

### What to Include

- **Description**: A detailed description of the vulnerability
- **Impact**: The potential impact of the vulnerability
- **Reproduction**: Steps to reproduce the vulnerability
- **Proof of Concept**: A proof of concept (if applicable)
- **Suggested Fix**: A suggested fix or mitigation (if known)

### Disclosure Policy

- **Private Disclosure**: Vulnerabilities are disclosed privately first
- **Patch Timeline**: Patches are released within a reasonable timeframe
- **Public Disclosure**: Public disclosure after a patch is available
- **Credit**: Reporters are credited in security advisories

## Additional Resources

- [RFC 4226 - HOTP](https://tools.ietf.org/html/rfc4226)
- [RFC 6238 - TOTP](https://tools.ietf.org/html/rfc6238)
- [RFC 4648 - Base32](https://tools.ietf.org/html/rfc4648)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
