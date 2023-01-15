package ebpf

import (
	"fmt"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestDrop(t *testing.T) {
	c := tNew(t)

	t.Run("drop ip", func(t *testing.T) {
		tWrappedFunc(c, "attach", func(e *EBPF) {
			address := fmt.Sprintf("%s:443", tFromIPStr)
			tTCPWrite(c, address, true)

			c.Assert(e.AddFromIP(tFromIP), qt.IsNil)

			tTCPWrite(c, address, false)
		})
	})

	t.Run("drop dns", func(t *testing.T) {
		tWrappedFunc(c, "attach", func(e *EBPF) {
			c.Assert(e.AddDNS(tDNS), qt.IsNil)

			_, err := tHTTPClient().Get(tDNShttps)
			c.Assert(err, qt.IsNotNil)
		})
	})

	t.Run("drop dns, too long", func(t *testing.T) {
		tWrappedFunc(c, "attach", func(e *EBPF) {
			maxLength := bytesLength - len(tDNS) - 1
			okUsage := fmt.Sprintf("%s.%s",
				strings.Repeat("a", maxLength),
				tDNS,
			)
			c.Assert(e.AddDNS(okUsage), qt.IsNil)

			wrongUsage := fmt.Sprintf("%s.%s",
				strings.Repeat("a", maxLength+1),
				tDNS,
			)
			err := e.AddDNS(wrongUsage)
			c.Assert(err, qt.IsNotNil)
			c.Assert(err, qt.ErrorMatches,
				fmt.Sprintf("%s is longer than %d characters", wrongUsage, bytesLength),
			)
		})
	})
}
