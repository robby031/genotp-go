package genotp

import (
	"bytes"
	"sort"
	"strings"
)

const maxContextFieldLen = 256

type OtpContext struct {
	bytes []byte
}

func NewOtpContext() *OtpContext {
	return &OtpContext{bytes: []byte{}}
}

func OtpContextFromBytes(b []byte) *OtpContext {
	return &OtpContext{bytes: b}
}

func (c *OtpContext) Bytes() []byte {
	return c.bytes
}

func (c *OtpContext) IsEmpty() bool {
	return len(c.bytes) == 0
}

type OtpContextBuilder struct {
	fields map[string]string
}

func NewOtpContextBuilder() *OtpContextBuilder {
	return &OtpContextBuilder{
		fields: make(map[string]string),
	}
}

func (b *OtpContextBuilder) IP(ip string) *OtpContextBuilder {
	if len(ip) <= maxContextFieldLen {
		b.fields["ip"] = ip
	}
	return b
}

func (b *OtpContextBuilder) Device(deviceID string) *OtpContextBuilder {
	if len(deviceID) <= maxContextFieldLen {
		b.fields["device"] = deviceID
	}
	return b
}

func (b *OtpContextBuilder) Session(session string) *OtpContextBuilder {
	if len(session) <= maxContextFieldLen {
		b.fields["session"] = session
	}
	return b
}

func (b *OtpContextBuilder) Origin(origin string) *OtpContextBuilder {
	normalized := normalizeOrigin(origin)
	if len(normalized) <= maxContextFieldLen {
		b.fields["origin"] = normalized
	}
	return b
}

func (b *OtpContextBuilder) Custom(key, value string) *OtpContextBuilder {
	if len(key) <= maxContextFieldLen && len(value) <= maxContextFieldLen {
		b.fields["x-"+key] = value
	}
	return b
}

func (b *OtpContextBuilder) Build() *OtpContext {
	keys := make([]string, 0, len(b.fields))
	for k := range b.fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(b.fields[k])
		buf.WriteByte(0)
	}

	return &OtpContext{bytes: buf.Bytes()}
}

func normalizeOrigin(origin string) string {
	origin = strings.TrimSpace(origin)
	origin = strings.ToLower(origin)

	if idx := strings.Index(origin, "#"); idx != -1 {
		origin = origin[:idx]
	}

	if idx := strings.Index(origin, "?"); idx != -1 {
		origin = origin[:idx]
	}

	if idx := strings.Index(origin, "://"); idx != -1 {
		scheme := origin[:idx]
		rest := origin[idx+3:]

		if idx2 := strings.Index(rest, "/"); idx2 != -1 {
			rest = rest[:idx2]
		}

		origin = scheme + "://" + rest
	}

	origin = strings.TrimSuffix(origin, "/")
	return origin
}
