package genotp_test

import (
	"testing"

	"github.com/robby031/genotp-go"
)

func TestOtpContextEmpty(t *testing.T) {
	ctx := genotp.NewOtpContext()
	if !ctx.IsEmpty() {
		t.Error("Empty context should be empty")
	}
	if len(ctx.Bytes()) != 0 {
		t.Error("Empty context should have no bytes")
	}
}

func TestOtpContextFromBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	ctx := genotp.OtpContextFromBytes(data)
	if ctx.IsEmpty() {
		t.Error("Context from bytes should not be empty")
	}
	if len(ctx.Bytes()) != 4 {
		t.Errorf("Expected 4 bytes, got %d", len(ctx.Bytes()))
	}
}

func TestOtpContextBuilderOrder(t *testing.T) {
	ctx1 := genotp.NewOtpContextBuilder().
		IP("10.0.0.1").
		Device("dev123").
		Session("sess456").
		Build()

	ctx2 := genotp.NewOtpContextBuilder().
		Session("sess456").
		Device("dev123").
		IP("10.0.0.1").
		Build()

	if string(ctx1.Bytes()) != string(ctx2.Bytes()) {
		t.Error("Builder order should not affect result")
	}
}

func TestOtpContextBuilderDifferentValues(t *testing.T) {
	ctx1 := genotp.NewOtpContextBuilder().IP("10.0.0.1").Build()
	ctx2 := genotp.NewOtpContextBuilder().IP("10.0.0.2").Build()

	if string(ctx1.Bytes()) == string(ctx2.Bytes()) {
		t.Error("Different values should produce different bytes")
	}
}

func TestNormalizeOrigin(t *testing.T) {
	ctx1 := genotp.NewOtpContextBuilder().Origin("https://EXAMPLE.com").Build()
	ctx2 := genotp.NewOtpContextBuilder().Origin("https://example.com/").Build()
	ctx3 := genotp.NewOtpContextBuilder().Origin("https://example.com/login?next=/home").Build()

	if string(ctx1.Bytes()) != string(ctx2.Bytes()) {
		t.Error("Origin normalization should handle case and trailing slash")
	}
	if string(ctx1.Bytes()) != string(ctx3.Bytes()) {
		t.Error("Origin normalization should strip path and query")
	}
}

func TestNormalizeOriginWithPort(t *testing.T) {
	ctx1 := genotp.NewOtpContextBuilder().Origin("https://example.com:8443/foo").Build()
	ctx2 := genotp.NewOtpContextBuilder().Origin("https://example.com:8443").Build()

	if string(ctx1.Bytes()) != string(ctx2.Bytes()) {
		t.Error("Origin normalization should keep port")
	}
}

func TestOtpContextBuilderCustomField(t *testing.T) {
	ctx := genotp.NewOtpContextBuilder().Custom("test", "value").Build()
	bytes := ctx.Bytes()
	if len(bytes) == 0 {
		t.Error("Custom field should add bytes")
	}
}
