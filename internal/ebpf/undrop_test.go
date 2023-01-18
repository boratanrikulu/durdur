package ebpf

import (
	"fmt"
	"net"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestUndrop(t *testing.T) {
	c := tNew(t)

	c.Run("undrop ip", func(c *qt.C) {
		newTWrap().Run(c, "drop-from", func(e *EBPF) {
			address := fmt.Sprintf("%s:443", tFromIPStr)
			TTCPWrite(c, address, false)

			c.Assert(e.UndropFrom(tFromIP), qt.IsNil)

			TTCPWrite(c, address, true)
		})
	})

	c.Run("undrop dns", func(c *qt.C) {
		newTWrap().Run(c, "drop-dns", func(e *EBPF) {
			c.Assert(e.UndropDNS(tDNS), qt.IsNil)

			_, err := net.LookupIP(tDNS)
			c.Assert(err, qt.IsNil)
		})
	})
}
