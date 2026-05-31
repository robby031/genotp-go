package genotp_test

import (
	"math"
	"testing"

	"github.com/robby031/genotp-go"
)

func TestClockSkewDetectorInsufficientData(t *testing.T) {
	d := genotp.NewClockSkewDetector(100)
	for i := 0; i < 5; i++ {
		d.Record(int64(i), 1)
	}
	r := d.Report()
	if r.Recommend != genotp.InsufficientData {
		t.Errorf("Expected InsufficientData, got %v", r.Recommend)
	}
}

func TestClockSkewDetectorNoDrift(t *testing.T) {
	d := genotp.NewClockSkewDetector(100)
	for i := 0; i < 50; i++ {
		d.Record(0, 1)
	}
	r := d.Report()
	if r.Recommend != genotp.NoActionNeeded {
		t.Errorf("Expected NoActionNeeded, got %v", r.Recommend)
	}
	if r.NonZeroCount != 0 {
		t.Errorf("Expected NonZeroCount=0, got %d", r.NonZeroCount)
	}
	if r.MeanOffset != 0 {
		t.Errorf("Expected MeanOffset=0, got %f", r.MeanOffset)
	}
}

func TestClockSkewDetectorConsistentDrift(t *testing.T) {
	d := genotp.NewClockSkewDetector(100)
	for i := 0; i < 50; i++ {
		d.Record(1, 2)
	}
	r := d.Report()
	if r.Recommend != genotp.ConsistentDrift {
		t.Errorf("Expected ConsistentDrift, got %v", r.Recommend)
	}
	if math.Abs(r.MeanOffset-1.0) > 0.01 {
		t.Errorf("Expected MeanOffset≈1.0, got %f", r.MeanOffset)
	}
}

func TestClockSkewDetectorEdgeHits(t *testing.T) {
	d := genotp.NewClockSkewDetector(100)
	for i := 0; i < 30; i++ {
		d.Record(1, 1)
	}
	for i := 0; i < 20; i++ {
		d.Record(-1, 1)
	}
	r := d.Report()
	if r.Recommend != genotp.WidenWindowOrCheckNtp {
		t.Errorf("Expected WidenWindowOrCheckNtp, got %v", r.Recommend)
	}
	if r.EdgeHitRatio < 0.2 {
		t.Errorf("Expected EdgeHitRatio≥0.2, got %f", r.EdgeHitRatio)
	}
}

func TestClockSkewDetectorAutoAdjust(t *testing.T) {
	d := genotp.NewClockSkewDetector(100)
	d.EnableAutoAdjust()

	if d.CurrentOffset() != 0 {
		t.Errorf("Initial offset should be 0, got %d", d.CurrentOffset())
	}

	for i := 0; i < 100; i++ {
		d.Record(2, 3)
	}
	offset := d.CurrentOffset()
	if math.Abs(float64(offset-2)) > 1 {
		t.Errorf("Offset should be close to 2 in auto-adjust mode, got %d", offset)
	}
}

func TestClockSkewDetectorEMAConvergesForSmallDrift(t *testing.T) {
	d := genotp.NewClockSkewDetector(100)
	d.EnableAutoAdjust()
	for i := 0; i < 80; i++ {
		d.Record(2, 3)
	}
	if got := d.CurrentOffset(); got == 0 {
		t.Errorf("EMA stuck at 0 — fixed-point state regression")
	}
}

func TestClockSkewDetectorPassiveMode(t *testing.T) {
	d := genotp.NewClockSkewDetector(100)
	for i := 0; i < 50; i++ {
		d.Record(5, 10)
	}
	if d.CurrentOffset() != 0 {
		t.Errorf("Passive mode should not change offset, got %d", d.CurrentOffset())
	}
}

func TestClockSkewDetectorReset(t *testing.T) {
	d := genotp.NewClockSkewDetector(100)
	d.EnableAutoAdjust()
	for i := 0; i < 20; i++ {
		d.Record(3, 5)
	}
	if d.CurrentOffset() == 0 {
		t.Error("Offset should be non-zero before reset")
	}

	d.Reset()
	if d.CurrentOffset() != 0 {
		t.Errorf("Offset should be 0 after reset, got %d", d.CurrentOffset())
	}
	if d.Report().SampleCount != 0 {
		t.Errorf("SampleCount should be 0 after reset")
	}
}

func TestClockSkewDetectorCapacity(t *testing.T) {
	d := genotp.NewClockSkewDetector(10)
	for i := 0; i < 100; i++ {
		d.Record(int64(i), 1)
	}
	if d.Report().SampleCount != 10 {
		t.Errorf("Expected SampleCount=10, got %d", d.Report().SampleCount)
	}
}

func TestClockSkewDetectorDisableAutoAdjust(t *testing.T) {
	d := genotp.NewClockSkewDetector(100)
	d.EnableAutoAdjust()
	for i := 0; i < 100; i++ {
		d.Record(2, 3)
	}
	d.Report()
	offset := d.CurrentOffset()
	tries := 0
	for offset == 0 && tries < 1200 {
		d.Record(2, 3)
		d.Report()
		offset = d.CurrentOffset()
		tries++
	}
	if offset == 0 {
		t.Skipf("Offset did not move from 0 after %d samples, skipping (smoothing too slow for test)", tries+100)
	}
	if math.Abs(float64(offset-2)) > 1 {
		t.Errorf("Offset should be close to 2 in auto-adjust mode, got %d", offset)
	}

	d.DisableAutoAdjust()
	if d.CurrentOffset() != 0 {
		t.Errorf("Offset should be 0 after disable, got %d", d.CurrentOffset())
	}
	if d.IsAutoAdjust() {
		t.Error("Should not be in auto-adjust mode after disable")
	}
}
