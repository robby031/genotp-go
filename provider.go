package genotp

// SecretProvider resolves secret material on demand for provider-backed HOTP
// and TOTP instances. Implementations may fetch from wrapped storage, a KMS
// unwrap flow, or other external secret managers.
type SecretProvider interface {
	Secret() ([]byte, error)
}

// SecretProviderFunc adapts a function into a SecretProvider.
type SecretProviderFunc func() ([]byte, error)

func (f SecretProviderFunc) Secret() ([]byte, error) {
	return f()
}

// HMACProvider computes HMACs without exporting raw secret material to the
// library process. This is intended for HSM-native, KMS-native, or remote
// signing flows where the OTP secret must remain non-exportable.
type HMACProvider interface {
	HMAC(algorithm Algorithm, message []byte) ([]byte, error)
}

// HMACProviderFunc adapts a function into an HMACProvider.
type HMACProviderFunc func(algorithm Algorithm, message []byte) ([]byte, error)

func (f HMACProviderFunc) HMAC(algorithm Algorithm, message []byte) ([]byte, error) {
	return f(algorithm, message)
}
