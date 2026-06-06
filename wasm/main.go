package main

import (
	"encoding/base64"
	"encoding/json"
	"time"
	"unsafe"

	genotp "github.com/robby031/genotp-go"
)

var (
	allocBuf  []byte
	resultBuf []byte
)

//go:wasmexport alloc
func wasmAlloc(size uint32) uint32 {
	allocBuf = make([]byte, size)
	if size == 0 {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(&allocBuf[0])))
}

//go:wasmexport result_ptr
func wasmResultPtr() uint32 {
	if len(resultBuf) == 0 {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(&resultBuf[0])))
}

//go:wasmexport result_len
func wasmResultLen() uint32 {
	return uint32(len(resultBuf))
}

type generateIn struct {
	Secret    string  `json:"secret"`
	Context   string  `json:"context"`
	Algorithm string  `json:"algorithm"`
	Digits    uint32  `json:"digits"`
	Period    uint64  `json:"period"`
	TimeUnix  *uint64 `json:"time_unix,omitempty"`
}

type generateOut struct {
	Code      string `json:"code"`
	ExpiresAt uint64 `json:"expires_at"`
}

//go:wasmexport generate
func wasmGenerate(inputPtr, inputLen uint32) int32 {
	in := allocBuf[:inputLen]
	_ = inputPtr

	var req generateIn
	if err := json.Unmarshal(in, &req); err != nil {
		setError(err.Error())
		return 1
	}

	secret, err := base64.StdEncoding.DecodeString(req.Secret)
	if err != nil {
		setError("invalid secret encoding")
		return 1
	}

	totp, err := genotp.NewTOTP(secret, parseAlgo(req.Algorithm), req.Digits, req.Period)
	if err != nil {
		setError(err.Error())
		return 1
	}

	var code string
	if req.Context != "" {
		ctxBytes, err := base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			setError("invalid context encoding")
			return 1
		}
		ctx := genotp.OtpContextFromBytes(ctxBytes)
		code, err = totp.GenBound(ctx, req.TimeUnix)
	} else {
		code, err = totp.Generate(req.TimeUnix)
	}
	if err != nil {
		setError(err.Error())
		return 1
	}

	var now uint64
	if req.TimeUnix != nil {
		now = *req.TimeUnix
	} else {
		now = uint64(time.Now().Unix())
	}
	expiresAt := (now/req.Period + 1) * req.Period

	resultBuf, _ = json.Marshal(generateOut{Code: code, ExpiresAt: expiresAt})
	return 0
}

type verifyIn struct {
	Code           string  `json:"code"`
	Secret         string  `json:"secret"`
	IssuedContext  string  `json:"issued_context"`
	RequestContext string  `json:"request_context"`
	Algorithm      string  `json:"algorithm"`
	Digits         uint32  `json:"digits"`
	Period         uint64  `json:"period"`
	Window         uint64  `json:"window"`
	TimeUnix       *uint64 `json:"time_unix,omitempty"`
}

type verifyOut struct {
	Valid bool `json:"valid"`
}

//go:wasmexport verify
func wasmVerify(inputPtr, inputLen uint32) int32 {
	in := allocBuf[:inputLen]
	_ = inputPtr

	var req verifyIn
	if err := json.Unmarshal(in, &req); err != nil {
		setError(err.Error())
		return 1
	}

	secret, err := base64.StdEncoding.DecodeString(req.Secret)
	if err != nil {
		setError("invalid secret encoding")
		return 1
	}

	totp, err := genotp.NewTOTP(secret, parseAlgo(req.Algorithm), req.Digits, req.Period)
	if err != nil {
		setError(err.Error())
		return 1
	}

	var valid bool
	if req.IssuedContext != "" || req.RequestContext != "" {
		issuedBytes, err := base64.StdEncoding.DecodeString(req.IssuedContext)
		if err != nil {
			setError("invalid issued_context encoding")
			return 1
		}
		requestBytes, err := base64.StdEncoding.DecodeString(req.RequestContext)
		if err != nil {
			setError("invalid request_context encoding")
			return 1
		}
		issuedCtx := genotp.OtpContextFromBytes(issuedBytes)
		requestCtx := genotp.OtpContextFromBytes(requestBytes)
		valid, err = totp.VerifyBound(req.Code, issuedCtx, req.TimeUnix, req.Window)
		if err != nil {
			setError(err.Error())
			return 1
		}
		// context match check (mirrors genotp-go Verifier.VerifyWithContext)
		if valid {
			if !constTimeEqBytes(issuedCtx.Bytes(), requestCtx.Bytes()) {
				valid = false
			}
		}
	} else {
		valid, err = totp.Verify(req.Code, req.TimeUnix, req.Window)
		if err != nil {
			setError(err.Error())
			return 1
		}
	}

	resultBuf, _ = json.Marshal(verifyOut{Valid: valid})
	return 0
}

type newSecretOut struct {
	SecretB64 string `json:"secret_b64"`
	SecretB32 string `json:"secret_b32"`
}

//go:wasmexport new_secret
func wasmNewSecret() int32 {
	secret, err := genotp.CreateSecret()
	if err != nil {
		setError(err.Error())
		return 1
	}
	resultBuf, _ = json.Marshal(newSecretOut{
		SecretB64: base64.StdEncoding.EncodeToString(secret),
		SecretB32: genotp.EncodeBase32(secret),
	})
	return 0
}

type buildContextIn struct {
	IP            string `json:"ip,omitempty"`
	Device        string `json:"device,omitempty"`
	Session       string `json:"session,omitempty"`
	Origin        string `json:"origin,omitempty"`
	Region        string `json:"region,omitempty"`
	GeoBucket     string `json:"geo_bucket,omitempty"`
	DistanceClass string `json:"distance_class,omitempty"`
}

type buildContextOut struct {
	Context string `json:"context"` // standard base64
}

//go:wasmexport build_context
func wasmBuildContext(inputPtr, inputLen uint32) int32 {
	in := allocBuf[:inputLen]
	_ = inputPtr

	var req buildContextIn
	if err := json.Unmarshal(in, &req); err != nil {
		setError(err.Error())
		return 1
	}

	b := genotp.NewOtpContextBuilder()
	if req.IP != "" {
		b.IP(req.IP)
	}
	if req.Device != "" {
		b.Device(req.Device)
	}
	if req.Session != "" {
		b.Session(req.Session)
	}
	if req.Origin != "" {
		b.Origin(req.Origin)
	}
	if req.Region != "" {
		b.Region(req.Region)
	}
	if req.GeoBucket != "" {
		b.GeoBucket(req.GeoBucket)
	}
	if req.DistanceClass != "" {
		b.DistanceClass(req.DistanceClass)
	}

	ctx := b.Build()
	resultBuf, _ = json.Marshal(buildContextOut{
		Context: base64.StdEncoding.EncodeToString(ctx.Bytes()),
	})
	return 0
}

// --- helpers ---

func setError(msg string) {
	type errOut struct {
		Error string `json:"error"`
	}
	resultBuf, _ = json.Marshal(errOut{Error: msg})
}

func parseAlgo(s string) genotp.Algorithm {
	switch s {
	case "SHA256":
		return genotp.SHA256
	case "SHA512":
		return genotp.SHA512
	default:
		return genotp.SHA1
	}
}

func constTimeEqBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func main() {}
