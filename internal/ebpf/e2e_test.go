package ebpf

import (
	"fmt"
	"net/http"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestE2E(t *testing.T) {
	c := tNew(t)

	address := fmt.Sprintf("%s:443", tFromIPStr)
	tWrappedFunc(c, "attach", func(e *EBPF) {
		c.Assert(e.AddDNS(tDNS), qt.IsNil)

		// After blocking a DNS, HTTP (domain - dns) calls are blocked.
		_, err := tHTTPClient().Get(tDNShttps)
		c.Assert(err, qt.IsNotNil)

		// But IP access is still open.
		tTCPWrite(c, address, true)

		c.Assert(e.AddFromIP(tFromIP), qt.IsNil)

		// After blocking the IP too, TCP (ip) access is blocked.
		tTCPWrite(c, address, false)
	})

	bothOk := func() {
		// After clearing the program, all is open.
		resp, err := tHTTPClient().Get(tDNShttps)
		c.Assert(err, qt.IsNil)
		c.Assert(resp.StatusCode, qt.Equals, http.StatusOK)

		tTCPWrite(c, address, true)
	}
	bothOk()

	tWrappedFunc(c, "attach", func(e *EBPF) {
		c.Assert(e.AddFromIP(tFromIP), qt.IsNil)

		// After blocking the IP, TCP (ip) access is blocked.
		tTCPWrite(c, address, false)

		// HTTP (domain - dns) calls are blocked too.
		_, err := tHTTPClient().Get(tDNShttps)
		c.Assert(err, qt.IsNotNil)
	})

	bothOk()
}
