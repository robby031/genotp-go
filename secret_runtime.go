package genotp

import (
	"crypto/hmac"
	"errors"
	"hash"
)

type secretRuntime struct {
	secret       []byte
	provider     SecretProvider
	hmacProvider HMACProvider
}

func newStaticSecretRuntime(secret []byte) secretRuntime {
	return secretRuntime{secret: secret}
}

func newProviderSecretRuntime(provider SecretProvider) secretRuntime {
	return secretRuntime{provider: provider}
}

func newHMACProviderRuntime(provider HMACProvider) secretRuntime {
	return secretRuntime{hmacProvider: provider}
}

func (r *secretRuntime) hasStaticSecret() bool {
	return len(r.secret) > 0
}

func (r *secretRuntime) clearStaticSecret() {
	for i := range r.secret {
		r.secret[i] = 0
	}
	r.secret = nil
}

func (r *secretRuntime) hasExternalProvider() bool {
	return r.provider != nil || r.hmacProvider != nil
}

func (r *secretRuntime) withMAC(hashFn func() hash.Hash, fn func(hash.Hash) uint32) (uint32, error) {
	if len(r.secret) > 0 {
		mac := hmac.New(hashFn, r.secret)
		return fn(mac), nil
	}

	if r.provider == nil {
		return 0, ErrInvalidSecret
	}

	secret, err := r.provider.Secret()
	if err != nil {
		return 0, errors.Join(ErrSecretProvider, err)
	}
	if len(secret) == 0 {
		return 0, ErrInvalidSecret
	}

	mac := hmac.New(hashFn, secret)
	out := fn(mac)
	for i := range secret {
		secret[i] = 0
	}
	return out, nil
}

func (r *secretRuntime) computeHMAC(algorithm Algorithm, hashFn func() hash.Hash, message []byte) ([]byte, error) {
	if r.hmacProvider != nil {
		sum, err := r.hmacProvider.HMAC(algorithm, message)
		if err != nil {
			return nil, errors.Join(ErrHMACProvider, err)
		}
		if len(sum) != expectedHMACSize(algorithm) {
			return nil, ErrHMACProvider
		}
		return sum, nil
	}

	var out []byte
	_, err := r.withMAC(hashFn, func(mac hash.Hash) uint32 {
		mac.Write(message)
		out = mac.Sum(nil)
		return 0
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func expectedHMACSize(algorithm Algorithm) int {
	switch algorithm {
	case SHA1:
		return 20
	case SHA256:
		return 32
	case SHA512:
		return 64
	default:
		return 0
	}
}
