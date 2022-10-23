package ebpf

import (
	"fmt"
	"net"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

func TestDrop(t *testing.T) {
	c := tNew(t)

	t.Run("drop", func(t *testing.T) {
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
}
