package genotp_test

import (
	"testing"

	"github.com/robby031/genotp-go/genotp"
)

func pickStr(data []byte, cur *int) string {
	if *cur >= len(data) {
		return ""
	}
	length := int(data[*cur])%32 + 1
	*cur++
	if *cur+length > len(data) {
		return ""
	}
	slice := data[*cur : *cur+length]
	*cur += length
	return string(slice)
}

func FuzzContextBuilder(f *testing.F) {
	data := []byte{
		0x05, 0x31, 0x32, 0x33, 0x34, 0x35,
		0x06, 0x64, 0x65, 0x76, 0x31, 0x32, 0x33,
		0x07, 0x73, 0x65, 0x73, 0x73, 0x31, 0x32, 0x33,
		0x15, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	}
	f.Add(data)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 8 {
			return
		}
		cur := 0

		ip := pickStr(data, &cur)
		device := pickStr(data, &cur)
		session := pickStr(data, &cur)
		origin := pickStr(data, &cur)

		a := genotp.NewOtpContextBuilder().IP(ip).Device(device).Session(session).Origin(origin).Build()
		b := genotp.NewOtpContextBuilder().Session(session).Origin(origin).IP(ip).Device(device).Build()

		if string(a.Bytes()) != string(b.Bytes()) {
			t.Error("setter order affects output")
		}

		altIP := ip + "x"
		c := genotp.NewOtpContextBuilder().IP(altIP).Device(device).Session(session).Origin(origin).Build()

		if string(a.Bytes()) == string(c.Bytes()) {
			t.Error("changed IP did not produce different output")
		}

		empty := genotp.NewOtpContext()
		if !empty.IsEmpty() {
			t.Error("empty context should be empty")
		}

		withCustom := genotp.NewOtpContextBuilder().Custom("ip", "foo").Build()
		withBuiltin := genotp.NewOtpContextBuilder().IP("foo").Build()

		if string(withCustom.Bytes()) == string(withBuiltin.Bytes()) {
			t.Error("custom() can simulate built-in field - x- prefix failed")
		}
	})
}
