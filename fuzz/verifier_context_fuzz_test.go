package genotp_test

import (
	"testing"

	"github.com/robby031/genotp-go"
)

func FuzzVerifierContext(f *testing.F) {
	data := []byte{
		0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
		0x05, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
	}
	f.Add(data)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 8 {
			return
		}

		codeLen := int(data[0])%16 + 1
		if len(data) < 1+codeLen+2 {
			return
		}

		code := make([]byte, codeLen)
		for i := 0; i < codeLen; i++ {
			code[i] = (data[1+i]%95 + 0x20)
		}
		codeStr := string(code)

		rest := data[1+codeLen:]
		if len(rest) < 2 {
			return
		}

		issuedLen := int(rest[0]) % 64
		requestLen := int(rest[1]) % 64
		body := rest[2:]
		if len(body) < issuedLen+requestLen {
			return
		}

		issuedBytes := body[:issuedLen]
		requestBytes := body[issuedLen : issuedLen+requestLen]

		issued := genotp.OtpContextFromBytes(issuedBytes)
		request := genotp.OtpContextFromBytes(requestBytes)

		verifier := genotp.NewVerifier(1000000)

		if string(issuedBytes) == string(requestBytes) {
			first := verifier.VerifyWithContext(codeStr, codeStr, issued, request)
			if first {
				second := verifier.VerifyWithContext(codeStr, codeStr, issued, request)
				if second {
					t.Error("replay context-match accepted twice")
				}
			}
		} else {
			result := verifier.VerifyWithContext(codeStr, codeStr, issued, request)
			if result {
				t.Error("context mismatch accepted")
			}
		}

		plain := verifier.VerifyWithReplayProtection(codeStr, codeStr)
		_ = plain
	})
}
