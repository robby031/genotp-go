package genotp

import (
	"strconv"
	"strings"
)

type OtpType int

const (
	HotpType OtpType = iota
	TotpType
)

type OtpAuthUri struct {
	typ       OtpType
	label     string
	secret    string
	issuer    string
	algorithm *Algorithm
	digits    *uint32
	period    *uint64
	counter   *uint64
}

func NewOtpAuthUri(typ OtpType, label, secret string) *OtpAuthUri {
	return &OtpAuthUri{
		typ:    typ,
		label:  label,
		secret: secret,
	}
}

func (u *OtpAuthUri) Issuer(issuer string) *OtpAuthUri {
	u.issuer = issuer
	return u
}

func (u *OtpAuthUri) Algorithm(algorithm Algorithm) *OtpAuthUri {
	u.algorithm = &algorithm
	return u
}

func (u *OtpAuthUri) Digits(digits uint32) *OtpAuthUri {
	u.digits = &digits
	return u
}

func (u *OtpAuthUri) Period(period uint64) *OtpAuthUri {
	u.period = &period
	return u
}

func (u *OtpAuthUri) Counter(counter uint64) *OtpAuthUri {
	u.counter = &counter
	return u
}

func (u *OtpAuthUri) Build() string {
	var uri strings.Builder

	typeStr := "totp"
	if u.typ == HotpType {
		typeStr = "hotp"
	}

	uri.WriteString("otpauth://")
	uri.WriteString(typeStr)
	uri.WriteByte('/')
	uri.WriteString(percentEncode(u.label))
	uri.WriteString("?secret=")

	normalized := normalizeBase32Secret(u.secret)
	uri.WriteString(percentEncode(normalized))

	if u.issuer != "" {
		uri.WriteString("&issuer=")
		uri.WriteString(percentEncode(u.issuer))
	}

	if u.algorithm != nil {
		uri.WriteString("&algorithm=")
		uri.WriteString(u.algorithm.String())
	}

	if u.digits != nil {
		uri.WriteString("&digits=")
		uri.WriteString(strconv.FormatUint(uint64(*u.digits), 10))
	}

	if u.period != nil {
		uri.WriteString("&period=")
		uri.WriteString(strconv.FormatUint(*u.period, 10))
	}

	if u.counter != nil {
		uri.WriteString("&counter=")
		uri.WriteString(strconv.FormatUint(*u.counter, 10))
	}

	return uri.String()
}

func (u *OtpAuthUri) String() string {
	return u.Build()
}

func percentEncode(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if shouldNotEncode(b) {
			buf.WriteByte(b)
		} else {
			buf.WriteByte('%')
			buf.WriteByte(hexUpper[b>>4])
			buf.WriteByte(hexUpper[b&0x0F])
		}
	}
	return buf.String()
}

const hexUpper = "0123456789ABCDEF"

func shouldNotEncode(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '-' || b == '.' || b == '_' || b == '~':
		return true
	}
	return false
}

func normalizeBase32Secret(s string) string {
	var result strings.Builder
	for _, c := range s {
		if c != '=' && !isWhitespace(c) {
			result.WriteRune(c)
		}
	}
	return result.String()
}

func isWhitespace(c rune) bool {
	switch c {
	case '\t', '\n', '\v', '\f', '\r', ' ',
		0x0085, // NEL
		0x00A0, // NBSP
		0x1680,
		0x2028, 0x2029,
		0x202F, 0x205F, 0x3000:
		return true
	}
	if c >= 0x2000 && c <= 0x200A {
		return true
	}
	return false
}
