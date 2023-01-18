package ebpf

import (
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

func Test_stringToBytes(t *testing.T) {
	c := tNew(t)

	c.Run("ok", func(c *qt.C) {
		s := strings.Repeat("a", bytesLength)

		b, err := stringToBytes(s)
		c.Assert(err, qt.IsNil)
		c.Assert(string(b[:]), qt.Equals, s)
	})

	c.Run("fail", func(c *qt.C) {
		s := strings.Repeat("a", bytesLength+1)

		_, err := stringToBytes(s)
		c.Assert(err, qt.IsNotNil)
		c.Assert(err, qt.ErrorIs, ErrInvalidUsage)
	})
}
