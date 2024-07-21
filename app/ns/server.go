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

// Server is a DNS server.
type Server struct {
	addr     string
	upstream string
	ttl      time.Duration

	cfg config.Config
	mu  sync.RWMutex

	dns *dns.Server
	ucl *dns.Client
}

// NewServer creates a new DNS server.
func NewServer(addr string, ttl time.Duration, upstream string) *Server {
	return &Server{
		addr:     addr,
		upstream: upstream,
		ttl:      ttl,
	}
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
		Addr:    s.addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handle),
	}

	s.ucl = &dns.Client{Net: "udp"}

	log.Printf("[INFO] starting server on %s", s.addr)
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

	for _, q := range req.Question {
		log.Printf("[INFO][%d] query for %s from %s", req.Id, q.Name, ip)
		for _, sec := range s.cfg.Sections {
			if !sec.From.Contains(ip) {
				continue
			}

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
						Ttl:    uint32(s.ttl.Seconds()),
					},
				})
				break
			}
		}
	}
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
	if s.upstream == "" {
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

	resp, _, err := s.ucl.Exchange(req, s.upstream)
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
