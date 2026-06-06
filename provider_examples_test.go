package genotp_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/robby031/genotp-go"
)

func ExampleNewTOTPFromSecretProvider() {
	encryptedSecret := []byte("wrapped-user-secret")

	provider := genotp.SecretProviderFunc(func() ([]byte, error) {
		// Replace this with a real KMS decrypt or secret manager fetch.
		_ = encryptedSecret
		return []byte("12345678901234567890"), nil
	})

	totp, err := genotp.NewTOTPFromSecretProvider(provider, genotp.SHA1, 6, 30)
	if err != nil {
		fmt.Println("build error:", err)
		return
	}

	timeVal := uint64(1234567890)
	code, err := totp.Generate(&timeVal)
	if err != nil {
		fmt.Println("generate error:", err)
		return
	}

	fmt.Println(code)
	// Output: 005924
}

func ExampleNewHOTPFromHMACProvider() {
	secret := []byte("12345678901234567890")

	provider := genotp.HMACProviderFunc(func(algorithm genotp.Algorithm, message []byte) ([]byte, error) {
		// Replace this with a real HSM/KMS MAC call.
		mac := hmac.New(sha256.New, secret)
		mac.Write(message)
		return mac.Sum(nil), nil
	})

	hotp, err := genotp.NewHOTPFromHMACProvider(provider, genotp.SHA256, 6)
	if err != nil {
		fmt.Println("build error:", err)
		return
	}

	code, err := hotp.Generate(12)
	if err != nil {
		fmt.Println("generate error:", err)
		return
	}

	fmt.Println(code)
	// Output: 360470
}
