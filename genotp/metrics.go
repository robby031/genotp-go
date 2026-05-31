package genotp

type Metrics struct {
	TotalGenerations        int64
	TotalVerifications      int64
	SuccessfulVerifications int64
	FailedVerifications     int64
}

func NewMetrics() *Metrics {
	return &Metrics{}
}

func (m *Metrics) RecordGeneration() {
	m.TotalGenerations++
}

func (m *Metrics) RecordVerification(success bool) {
	m.TotalVerifications++
	if success {
		m.SuccessfulVerifications++
	} else {
		m.FailedVerifications++
	}
}

func (m *Metrics) Reset() {
	m.TotalGenerations = 0
	m.TotalVerifications = 0
	m.SuccessfulVerifications = 0
	m.FailedVerifications = 0
}
