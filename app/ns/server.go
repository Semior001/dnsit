// Package ns contains the name server implementation.
package ns

import (
	"context"
	"log"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/Semior001/dnsit/app/config"
	"github.com/Semior001/dnsit/app/tailscale"
	"github.com/miekg/dns"
)

// Timeouts is a collection of various the DNS timeouts.
type Timeouts struct {
	Read     time.Duration `long:"read"  env:"READ"  description:"Read timeout"  default:"2s"`
	Write    time.Duration `long:"write" env:"WRITE" description:"Write timeout" default:"2s"`
	Idle     time.Duration `long:"idle"  env:"IDLE"  description:"Idle timeout"  default:"8s"`
	Upstream struct {
		Read    time.Duration `long:"read"    env:"READ"    description:"Read timeout"    default:"2s"`
		Write   time.Duration `long:"write"   env:"WRITE"   description:"Write timeout"   default:"2s"`
		Dial    time.Duration `long:"dial"    env:"DIAL"    description:"Dial timeout"    default:"2s"`
		Request time.Duration `long:"request" env:"REQUEST" description:"Request timeout"`
	} `group:"upstream" namespace:"upstream"`
}

// Server is a DNS server.
type Server struct {
	Addr     string
	Upstream string
	TTL      time.Duration
	TagStore tailscale.Interface
	Timeouts Timeouts

	cfg config.Config
	mu  sync.RWMutex

	dns *dns.Server
	ucl *dns.Client
}

// Run starts the DNS server and blocks until the context is canceled.
func (s *Server) Run(ctx context.Context) error {
	s.dns = &dns.Server{
		Addr: s.Addr,
		Net:  "udp",
		Handler: wrap(dns.HandlerFunc(s.serveUpstream),
			logMiddleware,
			s.handleSpecialQuery,
			s.handleAuthored),
		ReadTimeout:  s.Timeouts.Read,
		WriteTimeout: s.Timeouts.Write,
		IdleTimeout:  func() time.Duration { return s.Timeouts.Idle },
	}
	s.ucl = &dns.Client{
		Net:          "udp",
		Timeout:      s.Timeouts.Upstream.Request,
		DialTimeout:  s.Timeouts.Upstream.Dial,
		ReadTimeout:  s.Timeouts.Upstream.Read,
		WriteTimeout: s.Timeouts.Upstream.Write,
	}

	go func() {
		<-ctx.Done()
		log.Printf("[INFO] shutting down server")
		if err := s.dns.Shutdown(); err != nil {
			log.Printf("[ERROR] failed to shutdown server: %v", err)
		}
	}()

	log.Printf("[INFO] starting server on %s", s.Addr)
	return s.dns.ListenAndServe()
}

func (s *Server) matchesTS(req *dns.Msg, sec config.Section, ip net.IP) bool {
	if s.TagStore == nil || len(sec.TSTag) == 0 {
		return false
	}

	tags, err := s.TagStore.GetTags(ip)
	if err != nil {
		log.Printf("[WARN][%d] failed to get tags of %s: %v", req.Id, ip, err)
		return false
	}

	log.Printf("[DEBUG][%d] tags of %s: %v", req.Id, ip, tags)

	for _, tag := range tags {
		if _, ok := sec.TSTag[tag]; ok {
			return true
		}
	}

	return false
}

// SetConfig sets the server configuration.
func (s *Server) SetConfig(cfg config.Config) {
	log.Printf("[INFO] updating configuration to: %s", cfg)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cfg = cfg
}

func (s *Server) handleAuthored(next dns.Handler) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if !questionOfType(req, dns.TypeA) {
			next.ServeDNS(w, req)
			return
		}

		srcAddr, ok := w.RemoteAddr().(*net.UDPAddr)
		if !ok {
			log.Printf("[WARN] failed to get remote address - address is not a UDP address")
			next.ServeDNS(w, req)
			return
		}

		resp := s.answer(srcAddr.IP, req)
		if len(resp) == 0 {
			log.Printf("[DEBUG][%d] no answer found for %s", req.Id, srcAddr.IP)
			next.ServeDNS(w, req)
			return
		}

		msg := &dns.Msg{}
		msg.SetReply(req)
		msg.Answer = resp
		msg.Authoritative = true
		msg.RecursionAvailable = true
		if err := w.WriteMsg(msg); err != nil {
			log.Printf("[WARN][%d] failed to write message: %v", req.Id, err)
			sendError(dns.RcodeServerFailure, w, req)
		}
	})
}

func (s *Server) answer(src net.IP, req *dns.Msg) []dns.RR {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seek := func(q dns.Question, aliases []config.Alias) (result []dns.RR) {
		for _, alias := range aliases {
			if found := slices.Contains(alias.Hostnames, q.Name); !found {
				continue
			}

			ans := &dns.A{A: alias.IP, Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(s.TTL.Seconds()),
			}}
			result = append(result, ans)
		}

		return result
	}

	for _, q := range req.Question {
		log.Printf("[DEBUG][%d] querying for %s from %s", req.Id, q.Name, src)

		for idx := range s.cfg.Sections {
			matchedByCIDR := s.cfg.Sections[idx].CIDRContains(src)
			matchedByTS := s.matchesTS(req, s.cfg.Sections[idx], src)

			if !matchedByCIDR && !matchedByTS {
				continue
			}

			if ans := seek(q, s.cfg.Sections[idx].Aliases); len(ans) > 0 {
				return ans
			}
		}
	}

	return nil
}

func (s *Server) handleSpecialQuery(next dns.Handler) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		found := false
		for _, q := range req.Question {
			switch q.Name {
			case "semior001.dnsit.refresh-tailscale.":
				found = true
				if s.TagStore == nil {
					log.Printf("[WARN][%d] no tag store configured, but received refresh request", req.Id)
				}

				if err := s.TagStore.Refresh(ctx); err != nil {
					log.Printf("[WARN][%d] failed to refresh tailscale: %v", req.Id, err)
				}
			}
		}

		if found {
			// on special queries, always return NotImp,
			// regardless of the operation result
			sendError(dns.RcodeNotImplemented, w, req)
			return
		}

		next.ServeDNS(w, req)
	})
}

func (s *Server) serveUpstream(w dns.ResponseWriter, req *dns.Msg) {
	if s.Upstream == "" {
		log.Printf("[DEBUG][%d] no upstream server configured, returning server failure", req.Id)
		sendError(dns.RcodeNameError, w, req)
		return
	}

	resp, _, err := s.ucl.Exchange(req, s.Upstream)
	if err != nil {
		log.Printf("[WARN] failed to query upstream server: %v", err)
		return
	}

	if err = w.WriteMsg(resp); err != nil {
		log.Printf("[WARN] failed to write message: %v", err)
		sendError(dns.RcodeServerFailure, w, req)
	}
}

func questionOfType(req *dns.Msg, typ uint16) bool {
	for _, q := range req.Question {
		if q.Qtype == typ {
			return true
		}
	}
	return false
}

func sendError(code int, w dns.ResponseWriter, req *dns.Msg) {
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{
		Id:                 req.Id,
		Response:           true,
		Opcode:             req.Opcode,
		Authoritative:      true,
		RecursionDesired:   req.RecursionDesired,
		RecursionAvailable: true,
	}}
	msg.SetRcode(req, code)
	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[WARN][%d] failed to write message: %v", req.Id, err)
	}
}
