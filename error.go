package genotp

import "errors"

var (
	ErrInvalidSecret      = errors.New("invalid secret key")
	ErrInvalidCode        = errors.New("invalid OTP code")
	ErrInvalidDigits      = errors.New("invalid number of digits")
	ErrInvalidAlgorithm   = errors.New("invalid algorithm")
	ErrInvalidCounter     = errors.New("invalid counter value")
	ErrInvalidTime        = errors.New("invalid time value")
	ErrInvalidPeriod      = errors.New("invalid period value")
	ErrVerificationFailed = errors.New("OTP verification failed")
	ErrRateLimited        = errors.New("rate limited")
	ErrReplayAttack       = errors.New("replay attack detected")
)

type GenOtpError struct {
	Message string
}

func (e *GenOtpError) Error() string {
	return e.Message
}

func NewGenOtpError(msg string) *GenOtpError {
	return &GenOtpError{Message: msg}
}
