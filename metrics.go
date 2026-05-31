package genotp

import "sync/atomic"

type Metrics struct {
	HotpGenerations   atomic.Uint64
	HotpVerifications atomic.Uint64
	TotpGenerations   atomic.Uint64
	TotpVerifications atomic.Uint64
	Errors            atomic.Uint64
}

func NewMetrics() *Metrics {
	return &Metrics{}
}

func (m *Metrics) IncrementHotpGeneration() {
	m.HotpGenerations.Add(1)
}

func (m *Metrics) IncrementHotpVerification() {
	m.HotpVerifications.Add(1)
}

func (m *Metrics) IncrementTotpGeneration() {
	m.TotpGenerations.Add(1)
}

func (m *Metrics) IncrementTotpVerification() {
	m.TotpVerifications.Add(1)
}

func (m *Metrics) IncrementError() {
	m.Errors.Add(1)
}

func (m *Metrics) GetHotpGenerations() uint64 {
	return m.HotpGenerations.Load()
}

func (m *Metrics) GetHotpVerifications() uint64 {
	return m.HotpVerifications.Load()
}

func (m *Metrics) GetTotpGenerations() uint64 {
	return m.TotpGenerations.Load()
}

func (m *Metrics) GetTotpVerifications() uint64 {
	return m.TotpVerifications.Load()
}

func (m *Metrics) GetErrors() uint64 {
	return m.Errors.Load()
}

func (m *Metrics) Reset() {
	m.HotpGenerations.Store(0)
	m.HotpVerifications.Store(0)
	m.TotpGenerations.Store(0)
	m.TotpVerifications.Store(0)
	m.Errors.Store(0)
}
