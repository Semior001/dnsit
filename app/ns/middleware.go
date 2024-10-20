package ns

import (
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func wrap(handler dns.Handler, mws ...func(dns.Handler) dns.Handler) dns.Handler {
	for i := range mws {
		handler = mws[len(mws)-1-i](handler)
	}
	return handler
}

func logMiddleware(next dns.Handler) dns.Handler {
	getIP := func(w dns.ResponseWriter) string {
		if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			return addr.IP.String()
		}
		return "unknown"
	}

	return dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		var q []string
		for _, qq := range req.Question {
			q = append(q, qq.Name)
		}
		log.Printf("[INFO][%d] query for %v from %s",
			req.Id, strings.Join(q, ","), getIP(w))
		log.Printf("[DEBUG][%d] message: %v", req.Id, req)
		next.ServeDNS(w, req)
	})
}
