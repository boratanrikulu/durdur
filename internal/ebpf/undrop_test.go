package ebpf

import (
	"fmt"
	"net"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

func TestUndrop(t *testing.T) {
	c := tNew(t)

	t.Run("undrop", func(t *testing.T) {
		tWrappedFunc(c, "drop-from", func(e *EBPF) {
			address := fmt.Sprintf("%s:443", tFromIPStr)
			_, err := net.DialTimeout("tcp", address, 2*time.Second)
			c.Assert(err, qt.ErrorMatches, ".* i/o timeout")

			c.Assert(e.DeleteFromIP(tFromIP), qt.IsNil)

			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			c.Assert(err, qt.IsNil)
			defer conn.Close()

			_, err = conn.Write([]byte("hey"))
			c.Assert(err, qt.IsNil)
		})
	})
}
