package genotp

// VerifyResult holds the outcome of a single batch verification item.
type VerifyResult struct {
	OK  bool
	Err error
}

type HOTPVerifyRequest struct {
	Code    string
	Counter uint64
}

type HOTPVerifyBoundRequest struct {
	Code    string
	Counter uint64
	Context *OtpContext
}

type TOTPVerifyRequest struct {
	Code   string
	Time   *uint64
	Window uint64
}

type TOTPVerifyBoundRequest struct {
	Code    string
	Context *OtpContext
	Time    *uint64
	Window  uint64
}

// VerifyBatch verifies a batch of HOTP codes sequentially and returns one
// result per request. Each item preserves the same semantics as Verify.
func (h *HOTP) VerifyBatch(reqs []HOTPVerifyRequest) []VerifyResult {
	results := make([]VerifyResult, len(reqs))
	for i, req := range reqs {
		ok, err := h.Verify(req.Code, req.Counter)
		results[i] = VerifyResult{OK: ok, Err: err}
	}
	return results
}

// VerifyBoundBatch verifies a batch of context-bound HOTP codes sequentially
// and returns one result per request. Each item preserves the same semantics as
// VerifyBound.
func (h *HOTP) VerifyBoundBatch(reqs []HOTPVerifyBoundRequest) []VerifyResult {
	results := make([]VerifyResult, len(reqs))
	for i, req := range reqs {
		ok, err := h.VerifyBound(req.Code, req.Counter, req.Context)
		results[i] = VerifyResult{OK: ok, Err: err}
	}
	return results
}

// VerifyBatch verifies a batch of TOTP codes sequentially and returns one
// result per request. Each item preserves the same semantics as Verify.
func (t *TOTP) VerifyBatch(reqs []TOTPVerifyRequest) []VerifyResult {
	results := make([]VerifyResult, len(reqs))
	for i, req := range reqs {
		ok, err := t.Verify(req.Code, req.Time, req.Window)
		results[i] = VerifyResult{OK: ok, Err: err}
	}
	return results
}

// VerifyBoundBatch verifies a batch of context-bound TOTP codes sequentially
// and returns one result per request. Each item preserves the same semantics as
// VerifyBound.
func (t *TOTP) VerifyBoundBatch(reqs []TOTPVerifyBoundRequest) []VerifyResult {
	results := make([]VerifyResult, len(reqs))
	for i, req := range reqs {
		ok, err := t.VerifyBound(req.Code, req.Context, req.Time, req.Window)
		results[i] = VerifyResult{OK: ok, Err: err}
	}
	return results
}
