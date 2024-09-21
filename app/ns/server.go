// Package ns contains the name server implementation.
package ns

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Semior001/dnsit/app/config"
	"github.com/miekg/dns"
)

type tagStore interface {
	GetTags(ip net.IP) (tags []string, err error)
	Refresh(ctx context.Context) error
}

// Server is a DNS server.
type Server struct {
	Addr     string
	Upstream string
	TTL      time.Duration
	TagStore tagStore

	cfg config.Config
	mu  sync.RWMutex

	dns *dns.Server
	ucl *dns.Client
}

// Run starts the DNS server and blocks until the context is canceled.
func (s *Server) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		log.Printf("[INFO] shutting down server")
		if err := s.dns.Shutdown(); err != nil {
			log.Printf("[ERROR] failed to shutdown server: %v", err)
		}
	}()

	s.dns = &dns.Server{
		Addr:    s.Addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handle),
	}

	s.ucl = &dns.Client{Net: "udp"}

	log.Printf("[INFO] starting server on %s", s.Addr)
	return s.dns.ListenAndServe()
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	log.Printf("[DEBUG][%d] received message\n%s", req.Id, req)
	srcAddr, ok := w.RemoteAddr().(*net.UDPAddr)
	if !ok {
		log.Printf("[WARN] failed to get remote address - address is not a UDP address")
		return
	}

	msg := &dns.Msg{}
	msg.SetReply(req)

	if s.specialQuery(req) {
		// on special queries, always return server
		// failure, regardless of the operation result
		msg = &dns.Msg{MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: true,
		}}
		msg.SetRcode(req, dns.RcodeNameError)
		if err := w.WriteMsg(msg); err != nil {
			log.Printf("[WARN][%d] failed to write message: %v", req.Id, err)
		}
		return
	}

	s.matchAnswer(msg, req, srcAddr.IP)

	if len(msg.Answer) == 0 {
		log.Printf("[DEBUG][%d] no record found, serving to upstream", req.Id)
		s.serveUpstream(w, req)
		return
	}

	log.Printf("[INFO][%d] answering with %d IPs", req.Id, len(msg.Answer))
	log.Printf("[DEBUG][%d] answering with\n%s", req.Id, msg)
	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[WARN][%d] failed to write message: %v", req.Id, err)
	}
}

func (s *Server) matchAnswer(msg *dns.Msg, req *dns.Msg, ip net.IP) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	answer := func(sec config.Section, q dns.Question) (found bool) {
		for _, alias := range sec.Aliases {
			if found := matches(q.Name, alias.Hostnames); !found {
				continue
			}

			msg.Answer = append(msg.Answer, &dns.A{
				A: alias.IP,
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    uint32(s.TTL.Seconds()),
				},
			})

			return true
		}

		return false
	}

	for _, q := range req.Question {
		log.Printf("[INFO][%d] query for %s from %s", req.Id, q.Name, ip)
		for secIdx, sec := range s.cfg.Sections {
			matchedByCIDR := s.matchesCIDR(sec, ip)
			log.Printf("[DEBUG][%d] %2d | matched CIDR: %v", req.Id, secIdx, matchedByCIDR)
			if matchedByCIDR {
				if found := answer(sec, q); !found {
					continue
				}
				break
			}

			matchedByTS := s.matchesTS(req, sec, ip)
			log.Printf("[DEBUG][%d] %2d | matched TSTG: %v", req.Id, secIdx, matchedByTS)

			if matchedByTS {
				if found := answer(sec, q); !found {
					continue
				}
				break
			}
		}
	}
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

func (s *Server) matchesCIDR(section config.Section, ip net.IP) bool {
	return section.From != nil && section.From.Contains(ip)
}

func matches(name string, hostnames []string) (found bool) {
	for _, h := range hostnames {
		if h == name {
			found = true
			break
		}
	}
	return
}

func (s *Server) serveUpstream(w dns.ResponseWriter, req *dns.Msg) {
	if s.Upstream == "" {
		log.Printf("[DEBUG][%d] no upstream server configured, returning server failure", req.Id)
		msg := &dns.Msg{MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: true,
		}}
		msg.SetRcode(req, dns.RcodeNameError)
		if err := w.WriteMsg(msg); err != nil {
			log.Printf("[WARN][%d] failed to write message: %v", req.Id, err)
		}
		return
	}

	resp, _, err := s.ucl.Exchange(req, s.Upstream)
	if err != nil {
		log.Printf("[WARN] failed to query upstream server: %v", err)
		return
	}

	if err = w.WriteMsg(resp); err != nil {
		log.Printf("[WARN] failed to write message: %v", err)
	}
}

// SetConfig sets the server configuration.
func (s *Server) SetConfig(cfg config.Config) {
	log.Printf("[INFO] updating configuration to: %s", cfg)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cfg = cfg
}

func (s *Server) specialQuery(req *dns.Msg) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, q := range req.Question {
		if q.Name == "semior001.dnsit.refresh-tailscale." {
			log.Printf("[INFO][%d] received special query to refresh tailscale", req.Id)
			if s.TagStore != nil {
				if err := s.TagStore.Refresh(ctx); err != nil {
					log.Printf("[WARN][%d] failed to refresh tailscale: %v", req.Id, err)
				}
			}
			return true
		}
	}

	return false
}
