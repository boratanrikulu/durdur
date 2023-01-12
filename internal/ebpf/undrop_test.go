package ebpf

import (
	"fmt"
	"net"
	"net/http"
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

	t.Run("undrop", func(t *testing.T) {
		tWrappedFunc(c, "drop-dns", func(e *EBPF) {
			c.Assert(e.DeleteDNS(tDNS), qt.IsNil)

			resp, err := tHTTPClient().Get(tDNShttps)
			c.Assert(err, qt.IsNil)
			c.Assert(resp.StatusCode, qt.Equals, http.StatusOK)
		})
	})
}
