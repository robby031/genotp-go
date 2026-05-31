package genotp

import (
	"net/url"
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
	uri.WriteString(urlEncode(u.label))
	uri.WriteString("?secret=")

	normalized := normalizeBase32Secret(u.secret)
	uri.WriteString(urlEncode(normalized))

	if u.issuer != "" {
		uri.WriteString("&issuer=")
		uri.WriteString(urlEncode(u.issuer))
	}

	if u.algorithm != nil {
		uri.WriteString("&algorithm=")
		uri.WriteString(u.algorithm.String())
	}

	if u.digits != nil {
		uri.WriteString("&digits=")
		uri.WriteString(urlEncode(uintToString(*u.digits)))
	}

	if u.period != nil {
		uri.WriteString("&period=")
		uri.WriteString(urlEncode(uint64ToString(*u.period)))
	}

	if u.counter != nil {
		uri.WriteString("&counter=")
		uri.WriteString(urlEncode(uint64ToString(*u.counter)))
	}

	return uri.String()
}

func (u *OtpAuthUri) String() string {
	return u.Build()
}

func urlEncode(s string) string {
	return url.QueryEscape(s)
}

func normalizeBase32Secret(s string) string {
	var result strings.Builder
	for _, c := range s {
		if c != '=' && !strings.ContainsRune(" \t\n\r", c) {
			result.WriteRune(c)
		}
	}
	return result.String()
}

func uintToString(n uint32) string {
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if len(buf) == 0 {
		return "0"
	}
	return string(buf)
}

func uint64ToString(n uint64) string {
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if len(buf) == 0 {
		return "0"
	}
	return string(buf)
}
