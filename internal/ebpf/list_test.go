package ebpf

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestList(t *testing.T) {
	c := tNew(t)

	c.Run("list ip", func(c *qt.C) {
		newTWrap().Run(c, "drop-src", func(e *EBPF) {
			srcList, err := e.ListSrc()
			c.Assert(err, qt.IsNil)
			c.Assert(srcList, qt.HasLen, 1)
			c.Assert(srcList, qt.DeepEquals, map[string]int{
				tSrcIpStr: 0,
			})
		})
	})

	c.Run("list dns", func(c *qt.C) {
		newTWrap().Run(c, "drop-dns", func(e *EBPF) {
			srcList, err := e.ListDNS()
			c.Assert(err, qt.IsNil)
			c.Assert(srcList, qt.HasLen, 1)
			c.Assert(srcList, qt.DeepEquals, map[string]int{
				tDNS: 0,
			})
		})
	})

	c.Run("list ip and dns", func(c *qt.C) {
		newTWrap().Run(c, "attach", func(e *EBPF) {
			c.Assert(e.DropSrc(tSrcIP), qt.IsNil)
			c.Assert(e.DropDNS("bora.sh", "quik.bora.sh"), qt.IsNil)

			srcList, err := e.ListDNS()
			c.Assert(err, qt.IsNil)
			c.Assert(srcList, qt.HasLen, 2)
			c.Assert(srcList, qt.DeepEquals, map[string]int{
				"bora.sh":      0,
				"quik.bora.sh": 0,
			})

			TDNSLookup(c, "bora.sh", false)

			srcList, err = e.ListDNS()
			c.Assert(err, qt.IsNil)
			c.Assert(srcList, qt.HasLen, 2)
			c.Assert(srcList["bora.sh"], qt.Not(qt.Equals), 0)
			c.Assert(srcList["quik.bora.sh"], qt.Equals, 0)

			srcList, err = e.ListSrc()
			c.Assert(err, qt.IsNil)
			c.Assert(srcList, qt.HasLen, 1)
			c.Assert(srcList, qt.DeepEquals, map[string]int{
				tSrcIpStr: 0,
			})

			TTCPWrite(c, tSrcIpStr+":443", false)

			srcList, err = e.ListSrc()
			c.Assert(err, qt.IsNil)
			c.Assert(srcList, qt.HasLen, 1)
			c.Assert(srcList[tSrcIpStr], qt.Not(qt.Equals), 0)
		})
	})
}
