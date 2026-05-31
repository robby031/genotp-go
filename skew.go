package genotp

import (
	"math"
	"sync"
	"sync/atomic"
)

type SkewRecommendation int

const (
	InsufficientData SkewRecommendation = iota
	NoActionNeeded
	ConsistentDrift
	WidenWindowOrCheckNtp
)

func (r SkewRecommendation) String() string {
	switch r {
	case InsufficientData:
		return "InsufficientData"
	case NoActionNeeded:
		return "NoActionNeeded"
	case ConsistentDrift:
		return "ConsistentDrift"
	case WidenWindowOrCheckNtp:
		return "WidenWindowOrCheckNtp"
	default:
		return "Unknown"
	}
}

type SkewReport struct {
	SampleCount    int
	MeanOffset     float64
	NonZeroCount   int
	EdgeHitRatio   float64
	Recommendation SkewRecommendation
}

type skewState struct {
	buffer       []int64
	capacity     int
	writeIdx     int
	length       int
	sum          int64
	nonZeroCount int
}

type ClockSkewDetector struct {
	inner          sync.Mutex
	state          skewState
	autoAdjust     int32
	offset         int64
	lastWindowUsed int64
}

func NewClockSkewDetector(capacity int) *ClockSkewDetector {
	return &ClockSkewDetector{
		state: skewState{
			buffer:   make([]int64, 0, capacity),
			capacity: capacity,
		},
	}
}

func (d *ClockSkewDetector) Record(matchedOffset int64, windowUsed uint64) {
	d.inner.Lock()
	defer d.inner.Unlock()

	s := &d.state

	if s.length < s.capacity {
		s.buffer = append(s.buffer, matchedOffset)
		s.sum += matchedOffset
		if matchedOffset != 0 {
			s.nonZeroCount++
		}
		s.length++
		s.writeIdx = s.length % s.capacity
	} else {
		old := s.buffer[s.writeIdx]
		s.buffer[s.writeIdx] = matchedOffset

		s.sum = s.sum - old + matchedOffset

		if old != 0 {
			s.nonZeroCount--
		}
		if matchedOffset != 0 {
			s.nonZeroCount++
		}

		s.writeIdx = (s.writeIdx + 1) % s.capacity
	}

	atomic.StoreInt64(&d.lastWindowUsed, int64(windowUsed))

	if atomic.LoadInt32(&d.autoAdjust) == 1 && s.length >= 16 {
		mean := float64(s.sum) / float64(s.length)
		if math.Abs(mean) >= 0.5 {
			atomic.StoreInt64(&d.offset, int64(math.Round(mean)))
		} else {
			atomic.StoreInt64(&d.offset, 0)
		}
	}
}

func (d *ClockSkewDetector) CurrentOffset() int64 {
	return atomic.LoadInt64(&d.offset)
}

func (d *ClockSkewDetector) EnableAutoAdjust() {
	atomic.StoreInt32(&d.autoAdjust, 1)
}

func (d *ClockSkewDetector) DisableAutoAdjust() {
	atomic.StoreInt32(&d.autoAdjust, 0)
	atomic.StoreInt64(&d.offset, 0)
}

func (d *ClockSkewDetector) IsAutoAdjust() bool {
	return atomic.LoadInt32(&d.autoAdjust) == 1
}

func (d *ClockSkewDetector) Reset() {
	d.inner.Lock()
	defer d.inner.Unlock()

	d.state = skewState{
		buffer:   make([]int64, 0, d.state.capacity),
		capacity: d.state.capacity,
	}
	atomic.StoreInt64(&d.offset, 0)
}

func (d *ClockSkewDetector) Report() SkewReport {
	d.inner.Lock()
	defer d.inner.Unlock()

	s := &d.state
	sampleCount := s.length
	nonZeroCount := s.nonZeroCount
	windowUsed := atomic.LoadInt64(&d.lastWindowUsed)

	if sampleCount < 8 {
		return SkewReport{
			SampleCount:    sampleCount,
			MeanOffset:     0,
			NonZeroCount:   nonZeroCount,
			EdgeHitRatio:   0,
			Recommendation: InsufficientData,
		}
	}

	meanOffset := float64(s.sum) / float64(sampleCount)

	edgeHits := 0
	if windowUsed > 0 {
		for _, v := range s.buffer {
			if math.Abs(float64(v)) == float64(windowUsed) {
				edgeHits++
			}
		}
	}
	edgeHitRatio := float64(edgeHits) / float64(sampleCount)

	var recommendation SkewRecommendation
	if edgeHitRatio >= 0.2 {
		recommendation = WidenWindowOrCheckNtp
	} else if math.Abs(meanOffset) >= 0.5 {
		recommendation = ConsistentDrift
	} else {
		recommendation = NoActionNeeded
	}

	return SkewReport{
		SampleCount:    sampleCount,
		MeanOffset:     meanOffset,
		NonZeroCount:   nonZeroCount,
		EdgeHitRatio:   edgeHitRatio,
		Recommendation: recommendation,
	}
}
