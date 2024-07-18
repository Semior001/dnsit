// Package ns contains the name server implementation.
package ns

import (
	"context"
	"log"
	"net"

	"github.com/Semior001/dnsit/app/config"
	"github.com/miekg/dns"
)

// Server is a DNS server.
type Server struct {
	Addr     string
	Config   config.Config
	Upstream string

	srv *dns.Server
	ucl *dns.Client
}

// Run starts the DNS server and blocks until the context is canceled.
func (s *Server) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		log.Printf("[INFO] shutting down server")
		if err := s.srv.Shutdown(); err != nil {
			log.Printf("[ERROR] failed to shutdown server: %v", err)
		}
	}()

	s.srv = &dns.Server{
		Addr:    s.Addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handle),
	}

	s.ucl = &dns.Client{Net: "udp"}

	log.Printf("[INFO] starting server on %s", s.Addr)
	return s.srv.ListenAndServe()
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	log.Printf("[DEBUG][%d] received message\n%s", req.Id, req)
	srcAddr, ok := w.RemoteAddr().(*net.UDPAddr)
	if !ok {
		log.Printf("[WARN] failed to get remote address - address is not a UDP address")
		return
	}

	msg := &dns.Msg{
		Question: req.Question,
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: true,
		},
	}

	for _, q := range req.Question {
		log.Printf("[INFO][%d] query for %s from %s", req.Id, q.Name, srcAddr.IP)
		for _, sec := range s.Config.Sections {
			if !sec.From.Contains(srcAddr.IP) {
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
						Rrtype: q.Qtype,
						Class:  q.Qclass,
						Ttl:    60,
					},
				})
				break
			}
		}
	}

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

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("[WARN] failed to write message: %v", err)
	}
}
