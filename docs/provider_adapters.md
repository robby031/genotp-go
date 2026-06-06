# Provider Adapter Patterns

This guide shows practical adapter patterns for `SecretProvider` and
`HMACProvider` so users can connect genotp-go to external key-management
systems without changing the core OTP flow.

## When to use which provider

- Use `SecretProvider` when the secret is stored wrapped or encrypted at rest
  and your app can temporarily unwrap it at use time.
- Use `HMACProvider` when the secret must remain non-exportable and all MAC
  operations must happen inside an HSM, KMS MAC API, or remote signing system.

## SecretProvider with AWS KMS Decrypt

This pattern is suitable when your OTP secret is stored as ciphertext and AWS
KMS is used only to decrypt it on demand.

```go
package myotp

import (
    "context"

    "github.com/aws/aws-sdk-go-v2/service/kms"
    "github.com/robby031/genotp-go"
)

type AWSKMSSecretProvider struct {
    Client         *kms.Client
    CiphertextBlob []byte
    EncryptionCtx  map[string]string
    Ctx            context.Context
}

func (p *AWSKMSSecretProvider) Secret() ([]byte, error) {
    out, err := p.Client.Decrypt(p.Ctx, &kms.DecryptInput{
        CiphertextBlob:    p.CiphertextBlob,
        EncryptionContext: p.EncryptionCtx,
    })
    if err != nil {
        return nil, err
    }

    // Copy to a dedicated buffer so the caller can zero it after use.
    return append([]byte(nil), out.Plaintext...), nil
}
```

Usage:

```go
provider := &AWSKMSSecretProvider{
    Client:         kmsClient,
    CiphertextBlob: encryptedSecret,
    EncryptionCtx:  map[string]string{"tenant": "acme"},
    Ctx:            context.Background(),
}

totp, err := genotp.NewTOTPFromSecretProvider(provider, genotp.SHA1, 6, 30)
```

## Vault Transit as HMACProvider

This pattern is suitable when the OTP key must never leave the signing
boundary. Vault Transit computes the HMAC and returns only the digest.

```go
package myotp

import (
    "context"
    "encoding/base64"
    "fmt"
    "strings"

    vault "github.com/hashicorp/vault/api"
    "github.com/robby031/genotp-go"
)

type VaultTransitHMACProvider struct {
    Client  *vault.Client
    KeyName string
    Ctx     context.Context
}

func (p *VaultTransitHMACProvider) HMAC(algorithm genotp.Algorithm, message []byte) ([]byte, error) {
    algo, err := vaultHashName(algorithm)
    if err != nil {
        return nil, err
    }

    input := base64.StdEncoding.EncodeToString(message)
    path := fmt.Sprintf("transit/hmac/%s/%s", p.KeyName, algo)

    secret, err := p.Client.Logical().WriteWithContext(p.Ctx, path, map[string]any{
        "input": input,
    })
    if err != nil {
        return nil, err
    }

    raw, ok := secret.Data["hmac"].(string)
    if !ok || raw == "" {
        return nil, fmt.Errorf("vault transit returned empty hmac")
    }

    parts := strings.SplitN(raw, ":", 2)
    if len(parts) != 2 {
        return nil, fmt.Errorf("unexpected vault hmac format")
    }

    return base64.StdEncoding.DecodeString(parts[1])
}

func vaultHashName(algorithm genotp.Algorithm) (string, error) {
    switch algorithm {
    case genotp.SHA1:
        return "sha1", nil
    case genotp.SHA256:
        return "sha2-256", nil
    case genotp.SHA512:
        return "sha2-512", nil
    default:
        return "", fmt.Errorf("unsupported algorithm: %v", algorithm)
    }
}
```

Usage:

```go
provider := &VaultTransitHMACProvider{
    Client:  vaultClient,
    KeyName: "otp-user-42",
    Ctx:     context.Background(),
}

hotp, err := genotp.NewHOTPFromHMACProvider(provider, genotp.SHA256, 6)
```

## Design Notes

- `SecretProvider` improves encrypted-at-rest and secret-manager workflows, but
  the secret still becomes visible in process memory during HMAC computation.
- `HMACProvider` is the preferred path for true non-exportable OTP keys.
- Keep provider implementations deterministic and low-latency, especially for
  TOTP verification windows that may require multiple MAC operations.
- If your provider has high latency, consider caching outside the library with
  a strict TTL and a clear threat-model tradeoff.
