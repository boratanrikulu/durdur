package ebpf

import (
	"fmt"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestDrop(t *testing.T) {
	c := tNew(t)

	c.Run("drop ip", func(c *qt.C) {
		newTWrap().Run(c, "attach", func(e *EBPF) {
			address := fmt.Sprintf("%s:443", tSrcIpStr)
			TTCPWrite(c, address, true)

			c.Assert(e.DropSrc(tSrcIP), qt.IsNil)

			TTCPWrite(c, address, false)
		})
	})

	c.Run("drop dns", func(c *qt.C) {
		newTWrap().Run(c, "attach", func(e *EBPF) {
			c.Assert(e.DropDNS(tDNS), qt.IsNil)

			TDNSLookup(c, tDNS, false)
		})
	})

	c.Run("drop dns, too long", func(c *qt.C) {
		newTWrap().Run(c, "attach", func(e *EBPF) {
			maxLength := bytesLength - len(tDNS) - 1
			okUsage := fmt.Sprintf("%s.%s",
				strings.Repeat("a", maxLength),
				tDNS,
			)
			c.Assert(e.DropDNS(okUsage), qt.IsNil)

			wrongUsage := fmt.Sprintf("%s.%s", strings.Repeat("a", maxLength+1), tDNS)
			err := e.DropDNS(wrongUsage)
			c.Assert(err, qt.IsNotNil)
			c.Assert(err, qt.ErrorIs, ErrInvalidUsage)
		})
	})
}
