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

func TestOtpContextBuilderRegionNormalization(t *testing.T) {
	ctx1 := genotp.NewOtpContextBuilder().Region(" ID-LMG-BLULUK ").Build()
	ctx2 := genotp.NewOtpContextBuilder().Region("id-lmg-bluluk").Build()

	if string(ctx1.Bytes()) != string(ctx2.Bytes()) {
		t.Error("Region normalization should trim spaces and lowercase")
	}
}

func TestOtpContextBuilderGeoBucketNormalization(t *testing.T) {
	ctx1 := genotp.NewOtpContextBuilder().GeoBucket(" H3-8A2B ").Build()
	ctx2 := genotp.NewOtpContextBuilder().GeoBucket("h3-8a2b").Build()

	if string(ctx1.Bytes()) != string(ctx2.Bytes()) {
		t.Error("GeoBucket normalization should trim spaces and lowercase")
	}
}

func TestOtpContextBuilderDistanceClassValidation(t *testing.T) {
	ctx1 := genotp.NewOtpContextBuilder().DistanceClass(genotp.DistanceClassNearby).Build()
	ctx2 := genotp.NewOtpContextBuilder().DistanceClass(" Nearby ").Build()
	empty := genotp.NewOtpContextBuilder().DistanceClass("block_radius_250m").Build()

	if string(ctx1.Bytes()) != string(ctx2.Bytes()) {
		t.Error("DistanceClass should normalize valid values")
	}
	if !empty.IsEmpty() {
		t.Error("Invalid distance class should be ignored")
	}
}

func TestOtpContextBuilderLocationHelpersStableOrder(t *testing.T) {
	ctx1 := genotp.NewOtpContextBuilder().
		Region("id-lmg-bluluk").
		GeoBucket("cell-a1").
		DistanceClass(genotp.DistanceClassSameArea).
		Build()

	ctx2 := genotp.NewOtpContextBuilder().
		DistanceClass(genotp.DistanceClassSameArea).
		GeoBucket("cell-a1").
		Region("id-lmg-bluluk").
		Build()

	if string(ctx1.Bytes()) != string(ctx2.Bytes()) {
		t.Error("Location helper order should not affect result")
	}
}
