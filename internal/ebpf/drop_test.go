package ebpf

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

func TestDrop(t *testing.T) {
	c := tNew(t)

	t.Run("drop ip", func(t *testing.T) {
		tWrappedFunc(c, "attach", func(e *EBPF) {
			address := fmt.Sprintf("%s:443", tFromIPStr)
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			c.Assert(err, qt.IsNil)
			defer conn.Close()

			_, err = conn.Write([]byte("hey"))
			c.Assert(err, qt.IsNil)

			c.Assert(e.AddFromIP(tFromIP), qt.IsNil)

			_, err = net.DialTimeout("tcp", address, 2*time.Second)
			c.Assert(err, qt.ErrorMatches, ".* i/o timeout")
		})
	})

	t.Run("drop dns", func(t *testing.T) {
		tWrappedFunc(c, "attach", func(e *EBPF) {
			c.Assert(e.AddDNS(tDNS), qt.IsNil)

			_, err := http.Get(tDNShttps)
			c.Assert(err, qt.IsNotNil)
		})
	})

	t.Run("drop dns, too long", func(t *testing.T) {
		tWrappedFunc(c, "attach", func(e *EBPF) {
			maxLength := bytesLength - (len(tDNS) + 1)
			okUsage := fmt.Sprintf(".%s%s",
				strings.Repeat("a", maxLength),
				tDNS,
			)
			c.Assert(e.AddDNS(okUsage), qt.IsNil)

			wrongUsage := fmt.Sprintf(".%s%s",
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
