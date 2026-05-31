package genotp

import (
	"math"
	"testing"
)

func TestClockSkewDetectorInsufficientData(t *testing.T) {
	d := NewClockSkewDetector(100)
	for i := 0; i < 5; i++ {
		d.Record(int64(i), 1)
	}
	r := d.Report()
	if r.Recommendation != InsufficientData {
		t.Errorf("Expected InsufficientData, got %v", r.Recommendation)
	}
}

func TestClockSkewDetectorNoDrift(t *testing.T) {
	d := NewClockSkewDetector(100)
	for i := 0; i < 50; i++ {
		d.Record(0, 1)
	}
	r := d.Report()
	if r.Recommendation != NoActionNeeded {
		t.Errorf("Expected NoActionNeeded, got %v", r.Recommendation)
	}
	if r.NonZeroCount != 0 {
		t.Errorf("Expected NonZeroCount=0, got %d", r.NonZeroCount)
	}
	if r.MeanOffset != 0 {
		t.Errorf("Expected MeanOffset=0, got %f", r.MeanOffset)
	}
}

func TestClockSkewDetectorConsistentDrift(t *testing.T) {
	d := NewClockSkewDetector(100)
	for i := 0; i < 50; i++ {
		d.Record(1, 2)
	}
	r := d.Report()
	if r.Recommendation != ConsistentDrift {
		t.Errorf("Expected ConsistentDrift, got %v", r.Recommendation)
	}
	if math.Abs(r.MeanOffset-1.0) > 0.01 {
		t.Errorf("Expected MeanOffset≈1.0, got %f", r.MeanOffset)
	}
}

func TestClockSkewDetectorEdgeHits(t *testing.T) {
	d := NewClockSkewDetector(100)
	for i := 0; i < 30; i++ {
		d.Record(1, 1)
	}
	for i := 0; i < 20; i++ {
		d.Record(-1, 1)
	}
	r := d.Report()
	if r.Recommendation != WidenWindowOrCheckNtp {
		t.Errorf("Expected WidenWindowOrCheckNtp, got %v", r.Recommendation)
	}
	if r.EdgeHitRatio < 0.2 {
		t.Errorf("Expected EdgeHitRatio≥0.2, got %f", r.EdgeHitRatio)
	}
}

func TestClockSkewDetectorAutoAdjust(t *testing.T) {
	d := NewClockSkewDetector(100)
	d.EnableAutoAdjust()

	if d.CurrentOffset() != 0 {
		t.Errorf("Initial offset should be 0, got %d", d.CurrentOffset())
	}

	for i := 0; i < 20; i++ {
		d.Record(2, 3)
	}

	if d.CurrentOffset() != 2 {
		t.Errorf("Expected offset=2, got %d", d.CurrentOffset())
	}
}

func TestClockSkewDetectorPassiveMode(t *testing.T) {
	d := NewClockSkewDetector(100)
	for i := 0; i < 50; i++ {
		d.Record(5, 10)
	}
	if d.CurrentOffset() != 0 {
		t.Errorf("Passive mode should not change offset, got %d", d.CurrentOffset())
	}
}

func TestClockSkewDetectorReset(t *testing.T) {
	d := NewClockSkewDetector(100)
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
	d := NewClockSkewDetector(10)
	for i := 0; i < 100; i++ {
		d.Record(int64(i), 1)
	}
	if d.Report().SampleCount != 10 {
		t.Errorf("Expected SampleCount=10, got %d", d.Report().SampleCount)
	}
}

func TestClockSkewDetectorDisableAutoAdjust(t *testing.T) {
	d := NewClockSkewDetector(100)
	d.EnableAutoAdjust()
	for i := 0; i < 20; i++ {
		d.Record(2, 3)
	}
	if d.CurrentOffset() == 0 {
		t.Error("Offset should be non-zero in auto-adjust mode")
	}

	d.DisableAutoAdjust()
	if d.CurrentOffset() != 0 {
		t.Errorf("Offset should be 0 after disable, got %d", d.CurrentOffset())
	}
	if d.IsAutoAdjust() {
		t.Error("Should not be in auto-adjust mode after disable")
	}
}
