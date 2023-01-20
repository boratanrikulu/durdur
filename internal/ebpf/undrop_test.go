package ebpf

import (
	"fmt"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestUndrop(t *testing.T) {
	c := tNew(t)

	c.Run("undrop ip", func(c *qt.C) {
		newTWrap().Run(c, "drop-src", func(e *EBPF) {
			address := fmt.Sprintf("%s:443", tSrcIpStr)
			TTCPWrite(c, address, false)

			c.Assert(e.UndropSrc(tSrcIP), qt.IsNil)

			TTCPWrite(c, address, true)
		})
	})

	c.Run("undrop dns", func(c *qt.C) {
		newTWrap().Run(c, "drop-dns", func(e *EBPF) {
			c.Assert(e.UndropDNS(tDNS), qt.IsNil)

			TDNSLookup(c, tDNS, true)
		})
	})
}
