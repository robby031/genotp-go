package genotp

import (
	"math"
	"sync"
	"sync/atomic"
)

type SkewRecommend int

const (
	InsufficientData SkewRecommend = iota
	NoActionNeeded
	ConsistentDrift
	WidenWindowOrCheckNtp
)

func (r SkewRecommend) String() string {
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
	SampleCount  int
	MeanOffset   float64
	NonZeroCount int
	EdgeHitRatio float64
	Recommend    SkewRecommend
}

type skewState struct {
	buffer       []int64
	capacity     int
	writeIdx     int
	length       int
	sum          int64
	nonZeroCount int
}

const emaScale = 1000

type ClockSkewDetector struct {
	inner          sync.Mutex
	state          skewState
	autoAdjust     int32
	offset         int64
	smoothedScaled int64
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

	currentSum := s.sum
	currentLength := s.length
	d.inner.Unlock()

	atomic.StoreInt64(&d.lastWindowUsed, int64(windowUsed))

	if atomic.LoadInt32(&d.autoAdjust) == 1 && currentLength >= 16 {
		mean := float64(currentSum) / float64(currentLength)

		const alpha = 0.2
		prevScaled := atomic.LoadInt64(&d.smoothedScaled)
		prev := float64(prevScaled) / float64(emaScale)
		smoothed := alpha*mean + (1-alpha)*prev
		atomic.StoreInt64(&d.smoothedScaled, int64(math.Round(smoothed*float64(emaScale))))

		if math.Abs(smoothed) >= 0.5 {
			atomic.StoreInt64(&d.offset, int64(math.Round(smoothed)))
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
	atomic.StoreInt64(&d.smoothedScaled, 0)
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
	atomic.StoreInt64(&d.smoothedScaled, 0)
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
			SampleCount:  sampleCount,
			MeanOffset:   0,
			NonZeroCount: nonZeroCount,
			EdgeHitRatio: 0,
			Recommend:    InsufficientData,
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

	var recommend SkewRecommend
	switch {
	case edgeHitRatio >= 0.2:
		recommend = WidenWindowOrCheckNtp
	case math.Abs(meanOffset) >= 0.5:
		recommend = ConsistentDrift
	default:
		recommend = NoActionNeeded
	}

	return SkewReport{
		SampleCount:  sampleCount,
		MeanOffset:   meanOffset,
		NonZeroCount: nonZeroCount,
		EdgeHitRatio: edgeHitRatio,
		Recommend:    recommend,
	}
}
