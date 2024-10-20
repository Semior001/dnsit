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

		rr := &responseRecorder{ResponseWriter: w}
		next.ServeDNS(rr, req)

		ans := -1
		if rr.msg != nil {
			ans = len(rr.msg.Answer)
		}

		log.Printf("[INFO][%d] query %v from %s, responded with %d answers",
			req.Id, strings.Join(q, ", "), getIP(w), ans)
		log.Printf("[DEBUG][%d] request:\n%v", req.Id, req)
		log.Printf("[DEBUG][%d] response:\n%v", req.Id, rr.msg)
	})
}

type responseRecorder struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (rr *responseRecorder) WriteMsg(msg *dns.Msg) error {
	rr.msg = msg
	return rr.ResponseWriter.WriteMsg(msg)
}
