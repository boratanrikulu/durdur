package ebpf

import (
	"net"
	"net/http"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

var (
	tIface     *net.Interface // It is set by tNew().
	tIfaceStr  = "eth0"
	tFromIP    net.IP // It is set by tNew().
	tFromIPStr = "169.155.49.112"
	tDNShttps  = "https://quik.do"
	tDNS       = ".quik.do"
)

// tNew initializes testing variables and returns *qt.C.
func tNew(t *testing.T) *qt.C {
	c := qt.New(t)

	var err error
	tIface, err = net.InterfaceByName(tIfaceStr)
	if err != nil {
		c.Fatal(err)
	}
	tFromIP = net.ParseIP(tFromIPStr)

	return c
}

// tDoUntil is able to do pre-steps for testings.
// Supported until-steps;
// - attach
// - detach
// - drop-from
// - undrop-from
func tDoUntil(c *qt.C, e *EBPF, until string) {
	switch until {
	case "attach":
		c.Assert(e.Attach(tIface), qt.IsNil)
	case "detach":
		c.Assert(e.Attach(tIface), qt.IsNil)
		c.Assert(e.Detach(), qt.IsNil)
	case "drop-from":
		c.Assert(e.Attach(tIface), qt.IsNil)
		c.Assert(e.AddFromIP(tFromIP), qt.IsNil)
	case "undrop-from":
		c.Assert(e.Attach(tIface), qt.IsNil)
		c.Assert(e.AddFromIP(tFromIP), qt.IsNil)
		c.Assert(e.DeleteFromIP(tFromIP), qt.IsNil)
	case "drop-dns":
		c.Assert(e.Attach(tIface), qt.IsNil)
		c.Assert(e.AddDNS(tDNS), qt.IsNil)
	case "undrop-dns":
		c.Assert(e.Attach(tIface), qt.IsNil)
		c.Assert(e.AddDNS(tDNS), qt.IsNil)
		c.Assert(e.DeleteDNS(tDNS), qt.IsNil)
	default:
		c.Fatalf("%s until type is not supported", until)
	}
}

// tWrappedFunc follows these steps;
//   - makes until-steps
//   - does the job (f())
//   - detaches if it's needed
func tWrappedFunc(c *qt.C, until string, f func(e *EBPF)) {
	e, err := newEBPF()
	c.Assert(err, qt.IsNil)

	if until != "" {
		tDoUntil(c, e, until)
		tWait()
	}

	defer func() {
		if until != "detach" {
			tWait()
			if err := e.Detach(); err != nil {
				c.Fatalf("detach resources: %s", err)
			}
		}

		tWait()
	}()

	f(e)
}

// tWait waits.
func tWait() {
	time.Sleep(1 * time.Second) // TODO: remove this line.
}

// tTCPWrite tests the TCP connection through the address.
func tTCPWrite(c *qt.C, address string, ok bool) {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if !ok {
		c.Assert(err, qt.ErrorMatches, ".* i/o timeout")
		return
	}
	c.Assert(err, qt.IsNil)
	defer conn.Close()

	_, err = conn.Write([]byte("hey"))
	c.Assert(err, qt.IsNil)
}

func tHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 1 * time.Second,
	}
}
