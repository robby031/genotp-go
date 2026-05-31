package genotp

import "errors"

var (
	ErrInvalidSecret  = errors.New("invalid secret key")
	ErrInvalidCode    = errors.New("invalid OTP code")
	ErrInvalidDigits  = errors.New("invalid number of digits")
	ErrInvalidCounter = errors.New("invalid counter value")
	ErrInvalidTime    = errors.New("invalid time value")
	ErrInvalidPeriod  = errors.New("invalid period value")
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
